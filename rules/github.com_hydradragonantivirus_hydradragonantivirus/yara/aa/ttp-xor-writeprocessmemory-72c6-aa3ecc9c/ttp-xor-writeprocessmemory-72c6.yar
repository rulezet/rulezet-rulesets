rule TTP_XOR_WriteProcessMemory_72c6 {
  strings:
    $key_72c6 = { 25 b4 [2] 17 96 [2] 11 a3 [2] 3f a3 [2] 00 bf }

  condition:
    any of them
}