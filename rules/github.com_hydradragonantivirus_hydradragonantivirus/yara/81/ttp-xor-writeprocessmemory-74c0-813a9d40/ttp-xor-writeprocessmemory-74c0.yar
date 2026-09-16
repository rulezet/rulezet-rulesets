rule TTP_XOR_WriteProcessMemory_74c0 {
  strings:
    $key_74c0 = { 23 b2 [2] 11 90 [2] 17 a5 [2] 39 a5 [2] 06 b9 }

  condition:
    any of them
}