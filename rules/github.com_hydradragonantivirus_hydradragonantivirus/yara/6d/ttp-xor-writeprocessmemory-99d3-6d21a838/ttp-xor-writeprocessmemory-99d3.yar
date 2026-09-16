rule TTP_XOR_WriteProcessMemory_99d3 {
  strings:
    $key_99d3 = { ce a1 [2] fc 83 [2] fa b6 [2] d4 b6 [2] eb aa }

  condition:
    any of them
}