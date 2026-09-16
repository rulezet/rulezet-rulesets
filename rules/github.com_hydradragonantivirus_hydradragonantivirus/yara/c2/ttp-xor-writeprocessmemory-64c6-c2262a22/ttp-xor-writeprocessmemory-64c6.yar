rule TTP_XOR_WriteProcessMemory_64c6 {
  strings:
    $key_64c6 = { 33 b4 [2] 01 96 [2] 07 a3 [2] 29 a3 [2] 16 bf }

  condition:
    any of them
}