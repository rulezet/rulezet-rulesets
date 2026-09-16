rule TTP_XOR_WriteProcessMemory_bbb7 {
  strings:
    $key_bbb7 = { ec c5 [2] de e7 [2] d8 d2 [2] f6 d2 [2] c9 ce }

  condition:
    any of them
}