rule TTP_XOR_WriteProcessMemory_5cb4 {
  strings:
    $key_5cb4 = { 0b c6 [2] 39 e4 [2] 3f d1 [2] 11 d1 [2] 2e cd }

  condition:
    any of them
}