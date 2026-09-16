rule TTP_XOR_WriteProcessMemory_92ad {
  strings:
    $key_92ad = { c5 df [2] f7 fd [2] f1 c8 [2] df c8 [2] e0 d4 }

  condition:
    any of them
}