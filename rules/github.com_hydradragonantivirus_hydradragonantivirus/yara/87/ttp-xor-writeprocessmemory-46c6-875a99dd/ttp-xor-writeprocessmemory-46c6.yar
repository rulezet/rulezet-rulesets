rule TTP_XOR_WriteProcessMemory_46c6 {
  strings:
    $key_46c6 = { 11 b4 [2] 23 96 [2] 25 a3 [2] 0b a3 [2] 34 bf }

  condition:
    any of them
}