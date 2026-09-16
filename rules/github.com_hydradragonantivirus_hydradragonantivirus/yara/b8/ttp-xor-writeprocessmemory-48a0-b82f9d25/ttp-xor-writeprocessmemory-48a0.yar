rule TTP_XOR_WriteProcessMemory_48a0 {
  strings:
    $key_48a0 = { 1f d2 [2] 2d f0 [2] 2b c5 [2] 05 c5 [2] 3a d9 }

  condition:
    any of them
}