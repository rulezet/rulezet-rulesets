rule TTP_XOR_WriteProcessMemory_d984 {
  strings:
    $key_d984 = { 8e f6 [2] bc d4 [2] ba e1 [2] 94 e1 [2] ab fd }

  condition:
    any of them
}