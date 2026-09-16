rule TTP_XOR_WriteProcessMemory_78a9 {
  strings:
    $key_78a9 = { 2f db [2] 1d f9 [2] 1b cc [2] 35 cc [2] 0a d0 }

  condition:
    any of them
}