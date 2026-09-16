rule TTP_XOR_WriteProcessMemory_3bd1 {
  strings:
    $key_3bd1 = { 6c a3 [2] 5e 81 [2] 58 b4 [2] 76 b4 [2] 49 a8 }

  condition:
    any of them
}