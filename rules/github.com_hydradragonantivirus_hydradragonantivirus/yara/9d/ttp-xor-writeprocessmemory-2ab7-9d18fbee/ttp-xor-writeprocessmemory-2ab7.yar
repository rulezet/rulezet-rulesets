rule TTP_XOR_WriteProcessMemory_2ab7 {
  strings:
    $key_2ab7 = { 7d c5 [2] 4f e7 [2] 49 d2 [2] 67 d2 [2] 58 ce }

  condition:
    any of them
}