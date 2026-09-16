rule TTP_XOR_WriteProcessMemory_00b7 {
  strings:
    $key_00b7 = { 57 c5 [2] 65 e7 [2] 63 d2 [2] 4d d2 [2] 72 ce }

  condition:
    any of them
}