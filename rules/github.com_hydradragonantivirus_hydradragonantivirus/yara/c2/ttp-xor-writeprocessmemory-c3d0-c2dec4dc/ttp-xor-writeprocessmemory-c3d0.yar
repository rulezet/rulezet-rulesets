rule TTP_XOR_WriteProcessMemory_c3d0 {
  strings:
    $key_c3d0 = { 94 a2 [2] a6 80 [2] a0 b5 [2] 8e b5 [2] b1 a9 }

  condition:
    any of them
}