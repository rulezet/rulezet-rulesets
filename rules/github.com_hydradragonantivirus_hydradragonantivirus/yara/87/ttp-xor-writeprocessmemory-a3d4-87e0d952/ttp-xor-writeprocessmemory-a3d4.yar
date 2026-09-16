rule TTP_XOR_WriteProcessMemory_a3d4 {
  strings:
    $key_a3d4 = { f4 a6 [2] c6 84 [2] c0 b1 [2] ee b1 [2] d1 ad }

  condition:
    any of them
}