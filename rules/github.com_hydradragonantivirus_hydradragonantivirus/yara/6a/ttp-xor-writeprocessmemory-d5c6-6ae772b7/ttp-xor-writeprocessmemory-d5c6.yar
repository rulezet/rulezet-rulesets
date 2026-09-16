rule TTP_XOR_WriteProcessMemory_d5c6 {
  strings:
    $key_d5c6 = { 82 b4 [2] b0 96 [2] b6 a3 [2] 98 a3 [2] a7 bf }

  condition:
    any of them
}