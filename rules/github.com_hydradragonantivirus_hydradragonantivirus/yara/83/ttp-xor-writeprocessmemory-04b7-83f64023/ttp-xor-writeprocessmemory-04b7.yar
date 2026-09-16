rule TTP_XOR_WriteProcessMemory_04b7 {
  strings:
    $key_04b7 = { 53 c5 [2] 61 e7 [2] 67 d2 [2] 49 d2 [2] 76 ce }

  condition:
    any of them
}