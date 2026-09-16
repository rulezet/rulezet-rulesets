rule TTP_XOR_WriteProcessMemory_d0d1 {
  strings:
    $key_d0d1 = { 87 a3 [2] b5 81 [2] b3 b4 [2] 9d b4 [2] a2 a8 }

  condition:
    any of them
}