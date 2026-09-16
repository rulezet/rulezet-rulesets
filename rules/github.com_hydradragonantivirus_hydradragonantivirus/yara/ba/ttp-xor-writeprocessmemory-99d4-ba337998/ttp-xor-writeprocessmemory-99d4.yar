rule TTP_XOR_WriteProcessMemory_99d4 {
  strings:
    $key_99d4 = { ce a6 [2] fc 84 [2] fa b1 [2] d4 b1 [2] eb ad }

  condition:
    any of them
}