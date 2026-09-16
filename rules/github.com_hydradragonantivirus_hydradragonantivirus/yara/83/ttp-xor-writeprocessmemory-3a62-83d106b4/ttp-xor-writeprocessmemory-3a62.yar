rule TTP_XOR_WriteProcessMemory_3a62 {
  strings:
    $key_3a62 = { 6d 10 [2] 5f 32 [2] 59 07 [2] 77 07 [2] 48 1b }

  condition:
    any of them
}