rule TTP_XOR_WriteProcessMemory_13c6 {
  strings:
    $key_13c6 = { 44 b4 [2] 76 96 [2] 70 a3 [2] 5e a3 [2] 61 bf }

  condition:
    any of them
}