rule TTP_XOR_WriteProcessMemory_8262 {
  strings:
    $key_8262 = { d5 10 [2] e7 32 [2] e1 07 [2] cf 07 [2] f0 1b }

  condition:
    any of them
}