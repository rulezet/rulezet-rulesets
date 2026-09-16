rule TTP_XOR_WriteProcessMemory_86b7 {
  strings:
    $key_86b7 = { d1 c5 [2] e3 e7 [2] e5 d2 [2] cb d2 [2] f4 ce }

  condition:
    any of them
}