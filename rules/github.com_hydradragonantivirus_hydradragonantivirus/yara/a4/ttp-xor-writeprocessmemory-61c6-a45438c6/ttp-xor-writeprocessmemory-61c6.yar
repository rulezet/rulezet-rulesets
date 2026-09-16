rule TTP_XOR_WriteProcessMemory_61c6 {
  strings:
    $key_61c6 = { 36 b4 [2] 04 96 [2] 02 a3 [2] 2c a3 [2] 13 bf }

  condition:
    any of them
}