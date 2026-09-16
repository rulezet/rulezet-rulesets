rule TTP_XOR_WriteProcessMemory_36b7 {
  strings:
    $key_36b7 = { 61 c5 [2] 53 e7 [2] 55 d2 [2] 7b d2 [2] 44 ce }

  condition:
    any of them
}