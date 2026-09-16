rule TTP_XOR_WriteProcessMemory_1cb7 {
  strings:
    $key_1cb7 = { 4b c5 [2] 79 e7 [2] 7f d2 [2] 51 d2 [2] 6e ce }

  condition:
    any of them
}