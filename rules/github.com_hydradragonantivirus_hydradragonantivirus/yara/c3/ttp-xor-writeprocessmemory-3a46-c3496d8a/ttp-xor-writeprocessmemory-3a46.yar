rule TTP_XOR_WriteProcessMemory_3a46 {
  strings:
    $key_3a46 = { 6d 34 [2] 5f 16 [2] 59 23 [2] 77 23 [2] 48 3f }

  condition:
    any of them
}