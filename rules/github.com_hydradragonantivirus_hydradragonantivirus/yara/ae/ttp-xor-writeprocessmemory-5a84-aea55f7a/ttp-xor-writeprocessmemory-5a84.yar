rule TTP_XOR_WriteProcessMemory_5a84 {
  strings:
    $key_5a84 = { 0d f6 [2] 3f d4 [2] 39 e1 [2] 17 e1 [2] 28 fd }

  condition:
    any of them
}