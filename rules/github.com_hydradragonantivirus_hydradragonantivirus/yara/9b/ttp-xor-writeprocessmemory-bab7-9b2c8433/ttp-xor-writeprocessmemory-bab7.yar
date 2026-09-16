rule TTP_XOR_WriteProcessMemory_bab7 {
  strings:
    $key_bab7 = { ed c5 [2] df e7 [2] d9 d2 [2] f7 d2 [2] c8 ce }

  condition:
    any of them
}