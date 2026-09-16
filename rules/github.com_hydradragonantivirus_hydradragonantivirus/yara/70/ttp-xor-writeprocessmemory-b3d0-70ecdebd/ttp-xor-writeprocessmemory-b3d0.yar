rule TTP_XOR_WriteProcessMemory_b3d0 {
  strings:
    $key_b3d0 = { e4 a2 [2] d6 80 [2] d0 b5 [2] fe b5 [2] c1 a9 }

  condition:
    any of them
}