rule TTP_XOR_WriteProcessMemory_6898 {
  strings:
    $key_6898 = { 3f ea [2] 0d c8 [2] 0b fd [2] 25 fd [2] 1a e1 }

  condition:
    any of them
}