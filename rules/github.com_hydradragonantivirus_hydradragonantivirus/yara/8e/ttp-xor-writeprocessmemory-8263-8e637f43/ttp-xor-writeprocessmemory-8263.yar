rule TTP_XOR_WriteProcessMemory_8263 {
  strings:
    $key_8263 = { d5 11 [2] e7 33 [2] e1 06 [2] cf 06 [2] f0 1a }

  condition:
    any of them
}