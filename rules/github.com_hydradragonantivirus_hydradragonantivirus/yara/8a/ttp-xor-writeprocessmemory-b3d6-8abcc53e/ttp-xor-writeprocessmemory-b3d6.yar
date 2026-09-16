rule TTP_XOR_WriteProcessMemory_b3d6 {
  strings:
    $key_b3d6 = { e4 a4 [2] d6 86 [2] d0 b3 [2] fe b3 [2] c1 af }

  condition:
    any of them
}