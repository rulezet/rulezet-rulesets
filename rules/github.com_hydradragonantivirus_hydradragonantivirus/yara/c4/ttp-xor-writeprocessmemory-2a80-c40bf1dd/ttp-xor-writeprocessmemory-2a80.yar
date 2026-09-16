rule TTP_XOR_WriteProcessMemory_2a80 {
  strings:
    $key_2a80 = { 7d f2 [2] 4f d0 [2] 49 e5 [2] 67 e5 [2] 58 f9 }

  condition:
    any of them
}