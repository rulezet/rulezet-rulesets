rule TTP_XOR_WriteProcessMemory_01c6 {
  strings:
    $key_01c6 = { 56 b4 [2] 64 96 [2] 62 a3 [2] 4c a3 [2] 73 bf }

  condition:
    any of them
}