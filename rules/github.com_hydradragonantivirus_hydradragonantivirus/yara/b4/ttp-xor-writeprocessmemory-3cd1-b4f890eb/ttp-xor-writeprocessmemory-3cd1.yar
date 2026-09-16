rule TTP_XOR_WriteProcessMemory_3cd1 {
  strings:
    $key_3cd1 = { 6b a3 [2] 59 81 [2] 5f b4 [2] 71 b4 [2] 4e a8 }

  condition:
    any of them
}