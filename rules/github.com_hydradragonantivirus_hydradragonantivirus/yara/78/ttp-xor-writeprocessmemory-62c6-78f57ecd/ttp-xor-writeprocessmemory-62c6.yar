rule TTP_XOR_WriteProcessMemory_62c6 {
  strings:
    $key_62c6 = { 35 b4 [2] 07 96 [2] 01 a3 [2] 2f a3 [2] 10 bf }

  condition:
    any of them
}