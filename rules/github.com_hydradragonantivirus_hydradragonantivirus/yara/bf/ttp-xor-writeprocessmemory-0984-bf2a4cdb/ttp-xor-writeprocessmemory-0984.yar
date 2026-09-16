rule TTP_XOR_WriteProcessMemory_0984 {
  strings:
    $key_0984 = { 5e f6 [2] 6c d4 [2] 6a e1 [2] 44 e1 [2] 7b fd }

  condition:
    any of them
}