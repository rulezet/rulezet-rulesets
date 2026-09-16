rule TTP_XOR_WriteProcessMemory_e1b7 {
  strings:
    $key_e1b7 = { b6 c5 [2] 84 e7 [2] 82 d2 [2] ac d2 [2] 93 ce }

  condition:
    any of them
}