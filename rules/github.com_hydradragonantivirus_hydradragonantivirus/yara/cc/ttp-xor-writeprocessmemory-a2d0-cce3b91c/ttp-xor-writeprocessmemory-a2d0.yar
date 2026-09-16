rule TTP_XOR_WriteProcessMemory_a2d0 {
  strings:
    $key_a2d0 = { f5 a2 [2] c7 80 [2] c1 b5 [2] ef b5 [2] d0 a9 }

  condition:
    any of them
}