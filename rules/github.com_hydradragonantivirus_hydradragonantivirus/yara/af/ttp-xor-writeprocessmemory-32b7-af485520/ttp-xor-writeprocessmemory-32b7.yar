rule TTP_XOR_WriteProcessMemory_32b7 {
  strings:
    $key_32b7 = { 65 c5 [2] 57 e7 [2] 51 d2 [2] 7f d2 [2] 40 ce }

  condition:
    any of them
}