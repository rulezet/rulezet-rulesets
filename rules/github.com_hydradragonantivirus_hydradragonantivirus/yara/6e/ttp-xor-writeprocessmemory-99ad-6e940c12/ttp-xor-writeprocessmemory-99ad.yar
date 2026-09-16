rule TTP_XOR_WriteProcessMemory_99ad {
  strings:
    $key_99ad = { ce df [2] fc fd [2] fa c8 [2] d4 c8 [2] eb d4 }

  condition:
    any of them
}