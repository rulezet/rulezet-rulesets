rule TTP_XOR_WriteProcessMemory_2898 {
  strings:
    $key_2898 = { 7f ea [2] 4d c8 [2] 4b fd [2] 65 fd [2] 5a e1 }

  condition:
    any of them
}