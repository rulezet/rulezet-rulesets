rule TTP_XOR_WriteProcessMemory_3a22 {
  strings:
    $key_3a22 = { 6d 50 [2] 5f 72 [2] 59 47 [2] 77 47 [2] 48 5b }

  condition:
    any of them
}