rule TTP_XOR_WriteProcessMemory_8257 {
  strings:
    $key_8257 = { d5 25 [2] e7 07 [2] e1 32 [2] cf 32 [2] f0 2e }

  condition:
    any of them
}