rule TTP_XOR_WriteProcessMemory_2cb7 {
  strings:
    $key_2cb7 = { 7b c5 [2] 49 e7 [2] 4f d2 [2] 61 d2 [2] 5e ce }

  condition:
    any of them
}