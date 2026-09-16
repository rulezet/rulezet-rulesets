rule TTP_XOR_WriteProcessMemory_0ff6 {
  strings:
    $key_0ff6 = { 58 84 [2] 6a a6 [2] 6c 93 [2] 42 93 [2] 7d 8f }

  condition:
    any of them
}