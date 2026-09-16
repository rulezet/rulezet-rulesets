rule TTP_XOR_WriteProcessMemory_8226 {
  strings:
    $key_8226 = { d5 54 [2] e7 76 [2] e1 43 [2] cf 43 [2] f0 5f }

  condition:
    any of them
}