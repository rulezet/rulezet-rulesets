rule TTP_XOR_WriteProcessMemory_8272 {
  strings:
    $key_8272 = { d5 00 [2] e7 22 [2] e1 17 [2] cf 17 [2] f0 0b }

  condition:
    any of them
}