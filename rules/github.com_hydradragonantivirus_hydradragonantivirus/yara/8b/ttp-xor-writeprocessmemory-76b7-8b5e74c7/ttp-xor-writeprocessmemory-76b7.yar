rule TTP_XOR_WriteProcessMemory_76b7 {
  strings:
    $key_76b7 = { 21 c5 [2] 13 e7 [2] 15 d2 [2] 3b d2 [2] 04 ce }

  condition:
    any of them
}