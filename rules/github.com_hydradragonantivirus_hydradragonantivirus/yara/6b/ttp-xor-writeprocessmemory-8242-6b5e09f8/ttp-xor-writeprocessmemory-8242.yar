rule TTP_XOR_WriteProcessMemory_8242 {
  strings:
    $key_8242 = { d5 30 [2] e7 12 [2] e1 27 [2] cf 27 [2] f0 3b }

  condition:
    any of them
}