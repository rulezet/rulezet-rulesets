rule TTP_XOR_WriteProcessMemory_4898 {
  strings:
    $key_4898 = { 1f ea [2] 2d c8 [2] 2b fd [2] 05 fd [2] 3a e1 }

  condition:
    any of them
}