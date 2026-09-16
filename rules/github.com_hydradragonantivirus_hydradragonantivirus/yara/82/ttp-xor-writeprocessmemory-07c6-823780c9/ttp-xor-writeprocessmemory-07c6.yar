rule TTP_XOR_WriteProcessMemory_07c6 {
  strings:
    $key_07c6 = { 50 b4 [2] 62 96 [2] 64 a3 [2] 4a a3 [2] 75 bf }

  condition:
    any of them
}