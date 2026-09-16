rule TTP_XOR_WriteProcessMemory_41c6 {
  strings:
    $key_41c6 = { 16 b4 [2] 24 96 [2] 22 a3 [2] 0c a3 [2] 33 bf }

  condition:
    any of them
}