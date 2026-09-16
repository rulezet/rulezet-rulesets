rule TTP_XOR_WriteProcessMemory_4cb4 {
  strings:
    $key_4cb4 = { 1b c6 [2] 29 e4 [2] 2f d1 [2] 01 d1 [2] 3e cd }

  condition:
    any of them
}