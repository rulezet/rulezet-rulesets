rule TTP_XOR_WriteProcessMemory_3a21 {
  strings:
    $key_3a21 = { 6d 53 [2] 5f 71 [2] 59 44 [2] 77 44 [2] 48 58 }

  condition:
    any of them
}