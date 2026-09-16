rule TTP_XOR_WriteProcessMemory_5898 {
  strings:
    $key_5898 = { 0f ea [2] 3d c8 [2] 3b fd [2] 15 fd [2] 2a e1 }

  condition:
    any of them
}