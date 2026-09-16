rule TTP_XOR_WriteProcessMemory_71c4 {
  strings:
    $key_71c4 = { 26 b6 [2] 14 94 [2] 12 a1 [2] 3c a1 [2] 03 bd }

  condition:
    any of them
}