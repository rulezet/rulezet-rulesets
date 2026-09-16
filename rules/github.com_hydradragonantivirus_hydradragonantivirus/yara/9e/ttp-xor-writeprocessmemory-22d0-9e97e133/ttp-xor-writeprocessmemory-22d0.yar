rule TTP_XOR_WriteProcessMemory_22d0 {
  strings:
    $key_22d0 = { 75 a2 [2] 47 80 [2] 41 b5 [2] 6f b5 [2] 50 a9 }

  condition:
    any of them
}