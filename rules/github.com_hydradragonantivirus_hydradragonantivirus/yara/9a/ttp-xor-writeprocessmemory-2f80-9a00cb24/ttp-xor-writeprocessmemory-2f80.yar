rule TTP_XOR_WriteProcessMemory_2f80 {
  strings:
    $key_2f80 = { 78 f2 [2] 4a d0 [2] 4c e5 [2] 62 e5 [2] 5d f9 }

  condition:
    any of them
}