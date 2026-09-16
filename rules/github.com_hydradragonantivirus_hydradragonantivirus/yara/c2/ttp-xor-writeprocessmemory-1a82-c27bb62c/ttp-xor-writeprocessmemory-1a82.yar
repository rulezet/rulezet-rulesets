rule TTP_XOR_WriteProcessMemory_1a82 {
  strings:
    $key_1a82 = { 4d f0 [2] 7f d2 [2] 79 e7 [2] 57 e7 [2] 68 fb }

  condition:
    any of them
}