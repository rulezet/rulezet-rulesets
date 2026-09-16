rule TTP_XOR_WriteProcessMemory_3a66 {
  strings:
    $key_3a66 = { 6d 14 [2] 5f 36 [2] 59 03 [2] 77 03 [2] 48 1f }

  condition:
    any of them
}