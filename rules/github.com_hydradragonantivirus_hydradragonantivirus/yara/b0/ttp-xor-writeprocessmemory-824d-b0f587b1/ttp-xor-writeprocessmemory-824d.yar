rule TTP_XOR_WriteProcessMemory_824d {
  strings:
    $key_824d = { d5 3f [2] e7 1d [2] e1 28 [2] cf 28 [2] f0 34 }

  condition:
    any of them
}