rule TTP_XOR_WriteProcessMemory_72d1 {
  strings:
    $key_72d1 = { 25 a3 [2] 17 81 [2] 11 b4 [2] 3f b4 [2] 00 a8 }

  condition:
    any of them
}