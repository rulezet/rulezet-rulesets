rule TTP_XOR_WriteProcessMemory_40cc {
  strings:
    $key_40cc = { 17 be [2] 25 9c [2] 23 a9 [2] 0d a9 [2] 32 b5 }

  condition:
    any of them
}