rule TTP_XOR_WriteProcessMemory_8234 {
  strings:
    $key_8234 = { d5 46 [2] e7 64 [2] e1 51 [2] cf 51 [2] f0 4d }

  condition:
    any of them
}