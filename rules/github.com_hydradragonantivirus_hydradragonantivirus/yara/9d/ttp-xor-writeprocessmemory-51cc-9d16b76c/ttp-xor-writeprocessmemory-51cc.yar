rule TTP_XOR_WriteProcessMemory_51cc {
  strings:
    $key_51cc = { 06 be [2] 34 9c [2] 32 a9 [2] 1c a9 [2] 23 b5 }

  condition:
    any of them
}