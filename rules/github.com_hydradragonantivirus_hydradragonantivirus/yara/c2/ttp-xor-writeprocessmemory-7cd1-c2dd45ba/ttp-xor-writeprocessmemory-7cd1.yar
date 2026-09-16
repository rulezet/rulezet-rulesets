rule TTP_XOR_WriteProcessMemory_7cd1 {
  strings:
    $key_7cd1 = { 2b a3 [2] 19 81 [2] 1f b4 [2] 31 b4 [2] 0e a8 }

  condition:
    any of them
}