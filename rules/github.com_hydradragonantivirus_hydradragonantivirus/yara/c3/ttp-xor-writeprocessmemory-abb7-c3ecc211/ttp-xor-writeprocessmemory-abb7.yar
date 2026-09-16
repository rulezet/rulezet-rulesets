rule TTP_XOR_WriteProcessMemory_abb7 {
  strings:
    $key_abb7 = { fc c5 [2] ce e7 [2] c8 d2 [2] e6 d2 [2] d9 ce }

  condition:
    any of them
}