rule TTP_XOR_WriteProcessMemory_1fa3 {
  strings:
    $key_1fa3 = { 48 d1 [2] 7a f3 [2] 7c c6 [2] 52 c6 [2] 6d da }

  condition:
    any of them
}