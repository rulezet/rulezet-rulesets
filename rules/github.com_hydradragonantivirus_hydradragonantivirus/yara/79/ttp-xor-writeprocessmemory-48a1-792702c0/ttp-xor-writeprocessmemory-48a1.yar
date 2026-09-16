rule TTP_XOR_WriteProcessMemory_48a1 {
  strings:
    $key_48a1 = { 1f d3 [2] 2d f1 [2] 2b c4 [2] 05 c4 [2] 3a d8 }

  condition:
    any of them
}