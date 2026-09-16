rule TTP_XOR_WriteProcessMemory_71c6 {
  strings:
    $key_71c6 = { 26 b4 [2] 14 96 [2] 12 a3 [2] 3c a3 [2] 03 bf }

  condition:
    any of them
}