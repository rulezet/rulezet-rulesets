rule TTP_XOR_WriteProcessMemory_6ff6 {
  strings:
    $key_6ff6 = { 38 84 [2] 0a a6 [2] 0c 93 [2] 22 93 [2] 1d 8f }

  condition:
    any of them
}