rule TTP_XOR_WriteProcessMemory_b8ad {
  strings:
    $key_b8ad = { ef df [2] dd fd [2] db c8 [2] f5 c8 [2] ca d4 }

  condition:
    any of them
}