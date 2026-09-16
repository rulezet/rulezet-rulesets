rule TTP_XOR_WriteProcessMemory_76c6 {
  strings:
    $key_76c6 = { 21 b4 [2] 13 96 [2] 15 a3 [2] 3b a3 [2] 04 bf }

  condition:
    any of them
}