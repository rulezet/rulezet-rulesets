rule TTP_XOR_WriteProcessMemory_fbb7 {
  strings:
    $key_fbb7 = { ac c5 [2] 9e e7 [2] 98 d2 [2] b6 d2 [2] 89 ce }

  condition:
    any of them
}