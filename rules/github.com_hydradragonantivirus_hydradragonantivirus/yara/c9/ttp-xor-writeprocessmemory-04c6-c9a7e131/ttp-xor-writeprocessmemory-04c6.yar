rule TTP_XOR_WriteProcessMemory_04c6 {
  strings:
    $key_04c6 = { 53 b4 [2] 61 96 [2] 67 a3 [2] 49 a3 [2] 76 bf }

  condition:
    any of them
}