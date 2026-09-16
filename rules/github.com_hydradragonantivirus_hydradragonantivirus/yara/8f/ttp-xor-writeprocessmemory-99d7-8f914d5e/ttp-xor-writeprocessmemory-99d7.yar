rule TTP_XOR_WriteProcessMemory_99d7 {
  strings:
    $key_99d7 = { ce a5 [2] fc 87 [2] fa b2 [2] d4 b2 [2] eb ae }

  condition:
    any of them
}