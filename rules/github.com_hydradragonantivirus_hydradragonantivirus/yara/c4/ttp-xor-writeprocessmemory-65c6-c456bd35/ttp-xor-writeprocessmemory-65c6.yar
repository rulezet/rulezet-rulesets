rule TTP_XOR_WriteProcessMemory_65c6 {
  strings:
    $key_65c6 = { 32 b4 [2] 00 96 [2] 06 a3 [2] 28 a3 [2] 17 bf }

  condition:
    any of them
}