rule TTP_XOR_WriteProcessMemory_2f90 {
  strings:
    $key_2f90 = { 78 e2 [2] 4a c0 [2] 4c f5 [2] 62 f5 [2] 5d e9 }

  condition:
    any of them
}