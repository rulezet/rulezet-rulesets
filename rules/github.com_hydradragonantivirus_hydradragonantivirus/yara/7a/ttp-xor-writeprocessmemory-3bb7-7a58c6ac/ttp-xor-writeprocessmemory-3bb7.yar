rule TTP_XOR_WriteProcessMemory_3bb7 {
  strings:
    $key_3bb7 = { 6c c5 [2] 5e e7 [2] 58 d2 [2] 76 d2 [2] 49 ce }

  condition:
    any of them
}