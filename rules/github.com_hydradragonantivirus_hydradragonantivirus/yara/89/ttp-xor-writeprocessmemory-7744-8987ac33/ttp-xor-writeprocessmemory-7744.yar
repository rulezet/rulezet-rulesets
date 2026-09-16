rule TTP_XOR_WriteProcessMemory_7744 {
  strings:
    $key_7744 = { 20 36 [2] 12 14 [2] 14 21 [2] 3a 21 [2] 05 3d }

  condition:
    any of them
}