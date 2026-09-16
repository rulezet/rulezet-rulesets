rule TTP_XOR_WriteProcessMemory_66b7 {
  strings:
    $key_66b7 = { 31 c5 [2] 03 e7 [2] 05 d2 [2] 2b d2 [2] 14 ce }

  condition:
    any of them
}