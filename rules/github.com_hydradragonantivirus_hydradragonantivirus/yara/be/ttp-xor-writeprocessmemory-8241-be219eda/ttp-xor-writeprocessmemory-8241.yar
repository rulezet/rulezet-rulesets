rule TTP_XOR_WriteProcessMemory_8241 {
  strings:
    $key_8241 = { d5 33 [2] e7 11 [2] e1 24 [2] cf 24 [2] f0 38 }

  condition:
    any of them
}