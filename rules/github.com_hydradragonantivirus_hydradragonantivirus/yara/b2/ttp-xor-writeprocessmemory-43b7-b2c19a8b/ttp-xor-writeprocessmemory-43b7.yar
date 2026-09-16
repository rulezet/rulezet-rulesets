rule TTP_XOR_WriteProcessMemory_43b7 {
  strings:
    $key_43b7 = { 14 c5 [2] 26 e7 [2] 20 d2 [2] 0e d2 [2] 31 ce }

  condition:
    any of them
}