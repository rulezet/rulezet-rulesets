rule TTP_XOR_WriteProcessMemory_7cb7 {
  strings:
    $key_7cb7 = { 2b c5 [2] 19 e7 [2] 1f d2 [2] 31 d2 [2] 0e ce }

  condition:
    any of them
}