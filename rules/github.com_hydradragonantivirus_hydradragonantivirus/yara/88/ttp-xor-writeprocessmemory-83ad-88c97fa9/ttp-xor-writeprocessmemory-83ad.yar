rule TTP_XOR_WriteProcessMemory_83ad {
  strings:
    $key_83ad = { d4 df [2] e6 fd [2] e0 c8 [2] ce c8 [2] f1 d4 }

  condition:
    any of them
}