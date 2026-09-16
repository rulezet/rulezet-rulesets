rule TTP_XOR_WriteProcessMemory_c3d2 {
  strings:
    $key_c3d2 = { 94 a0 [2] a6 82 [2] a0 b7 [2] 8e b7 [2] b1 ab }

  condition:
    any of them
}