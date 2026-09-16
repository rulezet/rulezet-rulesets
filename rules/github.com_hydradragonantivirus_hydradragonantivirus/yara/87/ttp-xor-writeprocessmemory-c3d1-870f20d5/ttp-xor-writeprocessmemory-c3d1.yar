rule TTP_XOR_WriteProcessMemory_c3d1 {
  strings:
    $key_c3d1 = { 94 a3 [2] a6 81 [2] a0 b4 [2] 8e b4 [2] b1 a8 }

  condition:
    any of them
}