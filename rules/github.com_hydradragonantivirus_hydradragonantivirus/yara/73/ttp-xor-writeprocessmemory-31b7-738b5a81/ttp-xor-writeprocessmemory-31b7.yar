rule TTP_XOR_WriteProcessMemory_31b7 {
  strings:
    $key_31b7 = { 66 c5 [2] 54 e7 [2] 52 d2 [2] 7c d2 [2] 43 ce }

  condition:
    any of them
}