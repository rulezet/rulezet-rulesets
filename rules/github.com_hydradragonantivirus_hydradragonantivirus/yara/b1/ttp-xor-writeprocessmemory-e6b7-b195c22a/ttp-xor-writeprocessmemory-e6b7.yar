rule TTP_XOR_WriteProcessMemory_e6b7 {
  strings:
    $key_e6b7 = { b1 c5 [2] 83 e7 [2] 85 d2 [2] ab d2 [2] 94 ce }

  condition:
    any of them
}