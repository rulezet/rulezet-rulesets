rule TTP_XOR_WriteProcessMemory_1682 {
  strings:
    $key_1682 = { 41 f0 [2] 73 d2 [2] 75 e7 [2] 5b e7 [2] 64 fb }

  condition:
    any of them
}