rule TTP_XOR_WriteProcessMemory_71c0 {
  strings:
    $key_71c0 = { 26 b2 [2] 14 90 [2] 12 a5 [2] 3c a5 [2] 03 b9 }

  condition:
    any of them
}