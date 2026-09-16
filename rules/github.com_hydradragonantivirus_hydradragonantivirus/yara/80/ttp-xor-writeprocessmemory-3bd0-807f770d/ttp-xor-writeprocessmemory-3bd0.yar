rule TTP_XOR_WriteProcessMemory_3bd0 {
  strings:
    $key_3bd0 = { 6c a2 [2] 5e 80 [2] 58 b5 [2] 76 b5 [2] 49 a9 }

  condition:
    any of them
}