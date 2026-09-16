rule TTP_XOR_WriteProcessMemory_84ad {
  strings:
    $key_84ad = { d3 df [2] e1 fd [2] e7 c8 [2] c9 c8 [2] f6 d4 }

  condition:
    any of them
}