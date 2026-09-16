rule TTP_XOR_WriteProcessMemory_ffa6 {
  strings:
    $key_ffa6 = { a8 d4 [2] 9a f6 [2] 9c c3 [2] b2 c3 [2] 8d df }

  condition:
    any of them
}