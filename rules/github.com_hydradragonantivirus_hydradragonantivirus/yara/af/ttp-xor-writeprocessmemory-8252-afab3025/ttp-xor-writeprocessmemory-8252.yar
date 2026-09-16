rule TTP_XOR_WriteProcessMemory_8252 {
  strings:
    $key_8252 = { d5 20 [2] e7 02 [2] e1 37 [2] cf 37 [2] f0 2b }

  condition:
    any of them
}