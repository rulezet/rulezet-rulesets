rule TTP_XOR_WriteProcessMemory_f5b7 {
  strings:
    $key_f5b7 = { a2 c5 [2] 90 e7 [2] 96 d2 [2] b8 d2 [2] 87 ce }

  condition:
    any of them
}