rule TTP_XOR_WriteProcessMemory_46cc {
  strings:
    $key_46cc = { 11 be [2] 23 9c [2] 25 a9 [2] 0b a9 [2] 34 b5 }

  condition:
    any of them
}