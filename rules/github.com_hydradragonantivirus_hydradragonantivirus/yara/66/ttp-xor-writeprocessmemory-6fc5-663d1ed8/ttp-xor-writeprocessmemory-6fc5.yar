rule TTP_XOR_WriteProcessMemory_6fc5 {
  strings:
    $key_6fc5 = { 38 b7 [2] 0a 95 [2] 0c a0 [2] 22 a0 [2] 1d bc }

  condition:
    any of them
}