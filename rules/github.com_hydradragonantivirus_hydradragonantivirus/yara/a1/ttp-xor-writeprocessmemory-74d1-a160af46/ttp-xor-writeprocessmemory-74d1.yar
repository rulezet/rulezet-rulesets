rule TTP_XOR_WriteProcessMemory_74d1 {
  strings:
    $key_74d1 = { 23 a3 [2] 11 81 [2] 17 b4 [2] 39 b4 [2] 06 a8 }

  condition:
    any of them
}