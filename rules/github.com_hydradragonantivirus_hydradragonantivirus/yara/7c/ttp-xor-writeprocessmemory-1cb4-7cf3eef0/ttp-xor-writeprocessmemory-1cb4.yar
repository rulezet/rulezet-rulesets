rule TTP_XOR_WriteProcessMemory_1cb4 {
  strings:
    $key_1cb4 = { 4b c6 [2] 79 e4 [2] 7f d1 [2] 51 d1 [2] 6e cd }

  condition:
    any of them
}