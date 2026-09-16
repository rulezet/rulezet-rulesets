rule TTP_XOR_WriteProcessMemory_fab7 {
  strings:
    $key_fab7 = { ad c5 [2] 9f e7 [2] 99 d2 [2] b7 d2 [2] 88 ce }

  condition:
    any of them
}