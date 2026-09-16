rule TTP_XOR_WriteProcessMemory_05b7 {
  strings:
    $key_05b7 = { 52 c5 [2] 60 e7 [2] 66 d2 [2] 48 d2 [2] 77 ce }

  condition:
    any of them
}