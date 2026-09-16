rule TTP_XOR_WriteProcessMemory_d4c6 {
  strings:
    $key_d4c6 = { 83 b4 [2] b1 96 [2] b7 a3 [2] 99 a3 [2] a6 bf }

  condition:
    any of them
}