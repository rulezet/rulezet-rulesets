rule TTP_XOR_WriteProcessMemory_6fa6 {
  strings:
    $key_6fa6 = { 38 d4 [2] 0a f6 [2] 0c c3 [2] 22 c3 [2] 1d df }

  condition:
    any of them
}