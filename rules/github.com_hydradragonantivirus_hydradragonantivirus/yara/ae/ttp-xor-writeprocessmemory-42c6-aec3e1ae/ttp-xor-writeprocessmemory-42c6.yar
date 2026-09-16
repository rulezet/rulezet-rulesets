rule TTP_XOR_WriteProcessMemory_42c6 {
  strings:
    $key_42c6 = { 15 b4 [2] 27 96 [2] 21 a3 [2] 0f a3 [2] 30 bf }

  condition:
    any of them
}