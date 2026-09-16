rule TTP_XOR_WriteProcessMemory_47c6 {
  strings:
    $key_47c6 = { 10 b4 [2] 22 96 [2] 24 a3 [2] 0a a3 [2] 35 bf }

  condition:
    any of them
}