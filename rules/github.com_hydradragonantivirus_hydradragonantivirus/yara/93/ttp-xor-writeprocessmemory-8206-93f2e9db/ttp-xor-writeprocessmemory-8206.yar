rule TTP_XOR_WriteProcessMemory_8206 {
  strings:
    $key_8206 = { d5 74 [2] e7 56 [2] e1 63 [2] cf 63 [2] f0 7f }

  condition:
    any of them
}