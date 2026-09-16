rule TTP_XOR_WriteProcessMemory_8260 {
  strings:
    $key_8260 = { d5 12 [2] e7 30 [2] e1 05 [2] cf 05 [2] f0 19 }

  condition:
    any of them
}