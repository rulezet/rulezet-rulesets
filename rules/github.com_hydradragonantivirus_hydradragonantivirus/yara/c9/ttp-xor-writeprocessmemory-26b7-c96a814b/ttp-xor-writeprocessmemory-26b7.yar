rule TTP_XOR_WriteProcessMemory_26b7 {
  strings:
    $key_26b7 = { 71 c5 [2] 43 e7 [2] 45 d2 [2] 6b d2 [2] 54 ce }

  condition:
    any of them
}