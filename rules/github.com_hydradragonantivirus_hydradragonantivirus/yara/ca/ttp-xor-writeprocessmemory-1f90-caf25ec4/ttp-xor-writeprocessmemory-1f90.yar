rule TTP_XOR_WriteProcessMemory_1f90 {
  strings:
    $key_1f90 = { 48 e2 [2] 7a c0 [2] 7c f5 [2] 52 f5 [2] 6d e9 }

  condition:
    any of them
}