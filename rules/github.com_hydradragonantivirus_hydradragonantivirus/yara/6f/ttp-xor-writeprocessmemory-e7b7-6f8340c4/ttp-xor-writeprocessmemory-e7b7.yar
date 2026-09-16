rule TTP_XOR_WriteProcessMemory_e7b7 {
  strings:
    $key_e7b7 = { b0 c5 [2] 82 e7 [2] 84 d2 [2] aa d2 [2] 95 ce }

  condition:
    any of them
}