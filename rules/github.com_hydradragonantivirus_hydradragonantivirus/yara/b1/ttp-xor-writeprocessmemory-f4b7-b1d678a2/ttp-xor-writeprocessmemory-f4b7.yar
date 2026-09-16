rule TTP_XOR_WriteProcessMemory_f4b7 {
  strings:
    $key_f4b7 = { a3 c5 [2] 91 e7 [2] 97 d2 [2] b9 d2 [2] 86 ce }

  condition:
    any of them
}