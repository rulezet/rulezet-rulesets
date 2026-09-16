rule TTP_XOR_WriteProcessMemory_02b7 {
  strings:
    $key_02b7 = { 55 c5 [2] 67 e7 [2] 61 d2 [2] 4f d2 [2] 70 ce }

  condition:
    any of them
}