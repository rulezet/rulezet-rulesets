rule TTP_XOR_WriteProcessMemory_0a81 {
  strings:
    $key_0a81 = { 5d f3 [2] 6f d1 [2] 69 e4 [2] 47 e4 [2] 78 f8 }

  condition:
    any of them
}