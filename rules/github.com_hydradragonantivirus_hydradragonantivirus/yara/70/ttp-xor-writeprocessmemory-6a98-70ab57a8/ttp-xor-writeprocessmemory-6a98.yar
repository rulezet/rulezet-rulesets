rule TTP_XOR_WriteProcessMemory_6a98 {
  strings:
    $key_6a98 = { 3d ea [2] 0f c8 [2] 09 fd [2] 27 fd [2] 18 e1 }

  condition:
    any of them
}