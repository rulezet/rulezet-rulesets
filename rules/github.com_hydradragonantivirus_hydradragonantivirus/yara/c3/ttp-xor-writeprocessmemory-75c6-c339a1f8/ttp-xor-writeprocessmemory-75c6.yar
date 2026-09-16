rule TTP_XOR_WriteProcessMemory_75c6 {
  strings:
    $key_75c6 = { 22 b4 [2] 10 96 [2] 16 a3 [2] 38 a3 [2] 07 bf }

  condition:
    any of them
}