rule TTP_XOR_WriteProcessMemory_99d6 {
  strings:
    $key_99d6 = { ce a4 [2] fc 86 [2] fa b3 [2] d4 b3 [2] eb af }

  condition:
    any of them
}