rule TTP_XOR_WriteProcessMemory_30cc {
  strings:
    $key_30cc = { 67 be [2] 55 9c [2] 53 a9 [2] 7d a9 [2] 42 b5 }

  condition:
    any of them
}