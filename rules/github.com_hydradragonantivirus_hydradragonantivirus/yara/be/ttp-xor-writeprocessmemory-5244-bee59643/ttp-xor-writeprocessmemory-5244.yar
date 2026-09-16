rule TTP_XOR_WriteProcessMemory_5244 {
  strings:
    $key_5244 = { 05 36 [2] 37 14 [2] 31 21 [2] 1f 21 [2] 20 3d }

  condition:
    any of them
}