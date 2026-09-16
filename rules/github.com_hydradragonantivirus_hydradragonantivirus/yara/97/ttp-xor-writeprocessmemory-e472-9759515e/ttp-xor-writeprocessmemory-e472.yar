rule TTP_XOR_WriteProcessMemory_e472 {
  strings:
    $key_e472 = { b3 00 [2] 81 22 [2] 87 17 [2] a9 17 [2] 96 0b }

  condition:
    any of them
}