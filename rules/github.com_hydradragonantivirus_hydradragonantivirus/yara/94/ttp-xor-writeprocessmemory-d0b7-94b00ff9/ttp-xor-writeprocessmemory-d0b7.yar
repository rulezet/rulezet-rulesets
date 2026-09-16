rule TTP_XOR_WriteProcessMemory_d0b7 {
  strings:
    $key_d0b7 = { 87 c5 [2] b5 e7 [2] b3 d2 [2] 9d d2 [2] a2 ce }

  condition:
    any of them
}