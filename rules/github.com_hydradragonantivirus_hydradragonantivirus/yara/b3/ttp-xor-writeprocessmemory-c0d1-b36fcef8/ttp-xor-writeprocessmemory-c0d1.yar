rule TTP_XOR_WriteProcessMemory_c0d1 {
  strings:
    $key_c0d1 = { 97 a3 [2] a5 81 [2] a3 b4 [2] 8d b4 [2] b2 a8 }

  condition:
    any of them
}