rule TTP_XOR_WriteProcessMemory_e442 {
  strings:
    $key_e442 = { b3 30 [2] 81 12 [2] 87 27 [2] a9 27 [2] 96 3b }

  condition:
    any of them
}