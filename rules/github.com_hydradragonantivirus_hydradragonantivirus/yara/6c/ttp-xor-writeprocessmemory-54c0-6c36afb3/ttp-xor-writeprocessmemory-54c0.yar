rule TTP_XOR_WriteProcessMemory_54c0 {
  strings:
    $key_54c0 = { 03 b2 [2] 31 90 [2] 37 a5 [2] 19 a5 [2] 26 b9 }

  condition:
    any of them
}