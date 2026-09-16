rule TTP_XOR_WriteProcessMemory_3a60 {
  strings:
    $key_3a60 = { 6d 12 [2] 5f 30 [2] 59 05 [2] 77 05 [2] 48 19 }

  condition:
    any of them
}