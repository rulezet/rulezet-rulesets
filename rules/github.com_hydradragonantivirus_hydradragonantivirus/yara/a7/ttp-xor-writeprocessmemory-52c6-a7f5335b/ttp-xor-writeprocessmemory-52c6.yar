rule TTP_XOR_WriteProcessMemory_52c6 {
  strings:
    $key_52c6 = { 05 b4 [2] 37 96 [2] 31 a3 [2] 1f a3 [2] 20 bf }

  condition:
    any of them
}