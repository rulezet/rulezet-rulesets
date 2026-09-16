rule TTP_XOR_WriteProcessMemory_18b4 {
  strings:
    $key_18b4 = { 4f c6 [2] 7d e4 [2] 7b d1 [2] 55 d1 [2] 6a cd }

  condition:
    any of them
}