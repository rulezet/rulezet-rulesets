rule TTP_XOR_WriteProcessMemory_6f90 {
  strings:
    $key_6f90 = { 38 e2 [2] 0a c0 [2] 0c f5 [2] 22 f5 [2] 1d e9 }

  condition:
    any of them
}