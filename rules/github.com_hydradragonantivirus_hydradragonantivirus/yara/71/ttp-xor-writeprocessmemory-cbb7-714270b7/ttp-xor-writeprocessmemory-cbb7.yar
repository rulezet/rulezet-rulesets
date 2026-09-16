rule TTP_XOR_WriteProcessMemory_cbb7 {
  strings:
    $key_cbb7 = { 9c c5 [2] ae e7 [2] a8 d2 [2] 86 d2 [2] b9 ce }

  condition:
    any of them
}