rule TTP_XOR_WriteProcessMemory_8253 {
  strings:
    $key_8253 = { d5 21 [2] e7 03 [2] e1 36 [2] cf 36 [2] f0 2a }

  condition:
    any of them
}