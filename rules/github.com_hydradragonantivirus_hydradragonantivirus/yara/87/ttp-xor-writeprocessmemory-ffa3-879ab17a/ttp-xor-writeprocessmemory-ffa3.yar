rule TTP_XOR_WriteProcessMemory_ffa3 {
  strings:
    $key_ffa3 = { a8 d1 [2] 9a f3 [2] 9c c6 [2] b2 c6 [2] 8d da }

  condition:
    any of them
}