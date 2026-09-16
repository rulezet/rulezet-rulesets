rule TTP_XOR_WriteProcessMemory_99d0 {
  strings:
    $key_99d0 = { ce a2 [2] fc 80 [2] fa b5 [2] d4 b5 [2] eb a9 }

  condition:
    any of them
}