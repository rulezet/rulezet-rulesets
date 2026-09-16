rule TTP_XOR_WriteProcessMemory_95ad {
  strings:
    $key_95ad = { c2 df [2] f0 fd [2] f6 c8 [2] d8 c8 [2] e7 d4 }

  condition:
    any of them
}