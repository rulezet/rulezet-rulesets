rule TTP_XOR_WriteProcessMemory_47cc {
  strings:
    $key_47cc = { 10 be [2] 22 9c [2] 24 a9 [2] 0a a9 [2] 35 b5 }

  condition:
    any of them
}