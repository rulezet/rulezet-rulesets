rule TTP_XOR_WriteProcessMemory_12cc {
  strings:
    $key_12cc = { 45 be [2] 77 9c [2] 71 a9 [2] 5f a9 [2] 60 b5 }

  condition:
    any of them
}