rule TTP_XOR_WriteProcessMemory_d6c6 {
  strings:
    $key_d6c6 = { 81 b4 [2] b3 96 [2] b5 a3 [2] 9b a3 [2] a4 bf }

  condition:
    any of them
}