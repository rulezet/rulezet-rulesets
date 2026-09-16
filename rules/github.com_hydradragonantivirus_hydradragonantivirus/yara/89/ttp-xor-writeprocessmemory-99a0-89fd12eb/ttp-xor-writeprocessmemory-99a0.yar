rule TTP_XOR_WriteProcessMemory_99a0 {
  strings:
    $key_99a0 = { ce d2 [2] fc f0 [2] fa c5 [2] d4 c5 [2] eb d9 }

  condition:
    any of them
}