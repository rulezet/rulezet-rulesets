rule TTP_XOR_WriteProcessMemory_d0c6 {
  strings:
    $key_d0c6 = { 87 b4 [2] b5 96 [2] b3 a3 [2] 9d a3 [2] a2 bf }

  condition:
    any of them
}