rule TTP_XOR_WriteProcessMemory_11cc {
  strings:
    $key_11cc = { 46 be [2] 74 9c [2] 72 a9 [2] 5c a9 [2] 63 b5 }

  condition:
    any of them
}