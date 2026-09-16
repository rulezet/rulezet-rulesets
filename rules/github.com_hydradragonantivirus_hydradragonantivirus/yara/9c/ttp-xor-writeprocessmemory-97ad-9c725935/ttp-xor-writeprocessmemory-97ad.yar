rule TTP_XOR_WriteProcessMemory_97ad {
  strings:
    $key_97ad = { c0 df [2] f2 fd [2] f4 c8 [2] da c8 [2] e5 d4 }

  condition:
    any of them
}