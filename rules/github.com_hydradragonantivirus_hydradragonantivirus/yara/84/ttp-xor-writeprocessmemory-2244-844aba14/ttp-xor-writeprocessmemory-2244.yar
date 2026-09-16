rule TTP_XOR_WriteProcessMemory_2244 {
  strings:
    $key_2244 = { 75 36 [2] 47 14 [2] 41 21 [2] 6f 21 [2] 50 3d }

  condition:
    any of them
}