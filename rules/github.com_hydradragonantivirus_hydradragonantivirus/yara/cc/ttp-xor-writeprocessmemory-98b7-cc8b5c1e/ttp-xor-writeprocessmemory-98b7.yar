rule TTP_XOR_WriteProcessMemory_98b7 {
  strings:
    $key_98b7 = { cf c5 [2] fd e7 [2] fb d2 [2] d5 d2 [2] ea ce }

  condition:
    any of them
}