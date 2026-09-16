rule TTP_XOR_WriteProcessMemory_7984 {
  strings:
    $key_7984 = { 2e f6 [2] 1c d4 [2] 1a e1 [2] 34 e1 [2] 0b fd }

  condition:
    any of them
}