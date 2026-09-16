rule TTP_XOR_WriteProcessMemory_89b7 {
  strings:
    $key_89b7 = { de c5 [2] ec e7 [2] ea d2 [2] c4 d2 [2] fb ce }

  condition:
    any of them
}