rule TTP_XOR_WriteProcessMemory_8611 {
  strings:
    $key_8611 = { d1 63 [2] e3 41 [2] e5 74 [2] cb 74 [2] f4 68 }

  condition:
    any of them
}