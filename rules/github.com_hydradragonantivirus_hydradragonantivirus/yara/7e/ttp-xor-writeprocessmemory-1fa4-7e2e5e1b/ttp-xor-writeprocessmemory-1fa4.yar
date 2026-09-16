rule TTP_XOR_WriteProcessMemory_1fa4 {
  strings:
    $key_1fa4 = { 48 d6 [2] 7a f4 [2] 7c c1 [2] 52 c1 [2] 6d dd }

  condition:
    any of them
}