rule TTP_XOR_WriteProcessMemory_6fa4 {
  strings:
    $key_6fa4 = { 38 d6 [2] 0a f4 [2] 0c c1 [2] 22 c1 [2] 1d dd }

  condition:
    any of them
}