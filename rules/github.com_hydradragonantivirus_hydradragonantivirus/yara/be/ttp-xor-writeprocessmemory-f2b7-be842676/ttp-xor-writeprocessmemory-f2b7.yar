rule TTP_XOR_WriteProcessMemory_f2b7 {
  strings:
    $key_f2b7 = { a5 c5 [2] 97 e7 [2] 91 d2 [2] bf d2 [2] 80 ce }

  condition:
    any of them
}