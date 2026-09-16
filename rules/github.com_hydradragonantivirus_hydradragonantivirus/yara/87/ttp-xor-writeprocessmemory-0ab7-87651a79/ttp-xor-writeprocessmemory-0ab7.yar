rule TTP_XOR_WriteProcessMemory_0ab7 {
  strings:
    $key_0ab7 = { 5d c5 [2] 6f e7 [2] 69 d2 [2] 47 d2 [2] 78 ce }

  condition:
    any of them
}