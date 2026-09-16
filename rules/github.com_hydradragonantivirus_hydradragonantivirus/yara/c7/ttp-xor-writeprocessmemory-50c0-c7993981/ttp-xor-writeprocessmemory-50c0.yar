rule TTP_XOR_WriteProcessMemory_50c0 {
  strings:
    $key_50c0 = { 07 b2 [2] 35 90 [2] 33 a5 [2] 1d a5 [2] 22 b9 }

  condition:
    any of them
}