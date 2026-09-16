rule TTP_XOR_WriteProcessMemory_a3d2 {
  strings:
    $key_a3d2 = { f4 a0 [2] c6 82 [2] c0 b7 [2] ee b7 [2] d1 ab }

  condition:
    any of them
}