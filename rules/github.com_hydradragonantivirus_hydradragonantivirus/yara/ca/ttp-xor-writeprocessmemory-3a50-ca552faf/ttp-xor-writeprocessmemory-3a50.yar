rule TTP_XOR_WriteProcessMemory_3a50 {
  strings:
    $key_3a50 = { 6d 22 [2] 5f 00 [2] 59 35 [2] 77 35 [2] 48 29 }

  condition:
    any of them
}