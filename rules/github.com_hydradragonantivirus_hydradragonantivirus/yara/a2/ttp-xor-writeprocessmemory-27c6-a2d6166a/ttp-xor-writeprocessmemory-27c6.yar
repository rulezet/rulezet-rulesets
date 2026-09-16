rule TTP_XOR_WriteProcessMemory_27c6 {
  strings:
    $key_27c6 = { 70 b4 [2] 42 96 [2] 44 a3 [2] 6a a3 [2] 55 bf }

  condition:
    any of them
}