rule TTP_XOR_WriteProcessMemory_50c6 {
  strings:
    $key_50c6 = { 07 b4 [2] 35 96 [2] 33 a3 [2] 1d a3 [2] 22 bf }

  condition:
    any of them
}