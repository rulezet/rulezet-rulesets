rule TTP_XOR_WriteProcessMemory_b2d0 {
  strings:
    $key_b2d0 = { e5 a2 [2] d7 80 [2] d1 b5 [2] ff b5 [2] c0 a9 }

  condition:
    any of them
}