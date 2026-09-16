rule TTP_XOR_WriteProcessMemory_16b7 {
  strings:
    $key_16b7 = { 41 c5 [2] 73 e7 [2] 75 d2 [2] 5b d2 [2] 64 ce }

  condition:
    any of them
}