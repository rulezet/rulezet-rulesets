rule TTP_XOR_WriteProcessMemory_07cc {
  strings:
    $key_07cc = { 50 be [2] 62 9c [2] 64 a9 [2] 4a a9 [2] 75 b5 }

  condition:
    any of them
}