rule TTP_XOR_WriteProcessMemory_21cc {
  strings:
    $key_21cc = { 76 be [2] 44 9c [2] 42 a9 [2] 6c a9 [2] 53 b5 }

  condition:
    any of them
}