rule TTP_XOR_WriteProcessMemory_4f98 {
  strings:
    $key_4f98 = { 18 ea [2] 2a c8 [2] 2c fd [2] 02 fd [2] 3d e1 }

  condition:
    any of them
}