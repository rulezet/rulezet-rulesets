rule TTP_XOR_WriteProcessMemory_22c6 {
  strings:
    $key_22c6 = { 75 b4 [2] 47 96 [2] 41 a3 [2] 6f a3 [2] 50 bf }

  condition:
    any of them
}