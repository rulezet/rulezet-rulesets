rule TTP_XOR_WriteProcessMemory_3a41 {
  strings:
    $key_3a41 = { 6d 33 [2] 5f 11 [2] 59 24 [2] 77 24 [2] 48 38 }

  condition:
    any of them
}