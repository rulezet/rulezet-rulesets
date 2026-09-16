rule TTP_XOR_WriteProcessMemory_8247 {
  strings:
    $key_8247 = { d5 35 [2] e7 17 [2] e1 22 [2] cf 22 [2] f0 3e }

  condition:
    any of them
}