rule TTP_XOR_WriteProcessMemory_90b7 {
  strings:
    $key_90b7 = { c7 c5 [2] f5 e7 [2] f3 d2 [2] dd d2 [2] e2 ce }

  condition:
    any of them
}