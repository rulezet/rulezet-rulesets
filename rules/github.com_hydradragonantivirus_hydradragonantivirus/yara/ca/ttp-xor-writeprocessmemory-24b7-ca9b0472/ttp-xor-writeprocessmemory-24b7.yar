rule TTP_XOR_WriteProcessMemory_24b7 {
  strings:
    $key_24b7 = { 73 c5 [2] 41 e7 [2] 47 d2 [2] 69 d2 [2] 56 ce }

  condition:
    any of them
}