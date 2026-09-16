rule TTP_XOR_WriteProcessMemory_4f90 {
  strings:
    $key_4f90 = { 18 e2 [2] 2a c0 [2] 2c f5 [2] 02 f5 [2] 3d e9 }

  condition:
    any of them
}