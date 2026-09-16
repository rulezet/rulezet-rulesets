rule TTP_XOR_WriteProcessMemory_e2b7 {
  strings:
    $key_e2b7 = { b5 c5 [2] 87 e7 [2] 81 d2 [2] af d2 [2] 90 ce }

  condition:
    any of them
}