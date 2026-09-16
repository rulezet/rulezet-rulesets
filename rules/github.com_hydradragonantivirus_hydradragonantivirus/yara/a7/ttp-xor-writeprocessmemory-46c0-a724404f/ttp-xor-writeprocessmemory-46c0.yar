rule TTP_XOR_WriteProcessMemory_46c0 {
  strings:
    $key_46c0 = { 11 b2 [2] 23 90 [2] 25 a5 [2] 0b a5 [2] 34 b9 }

  condition:
    any of them
}