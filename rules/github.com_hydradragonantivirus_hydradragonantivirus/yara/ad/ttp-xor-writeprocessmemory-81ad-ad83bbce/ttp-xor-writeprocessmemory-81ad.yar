rule TTP_XOR_WriteProcessMemory_81ad {
  strings:
    $key_81ad = { d6 df [2] e4 fd [2] e2 c8 [2] cc c8 [2] f3 d4 }

  condition:
    any of them
}