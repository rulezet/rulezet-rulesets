rule TTP_XOR_WriteProcessMemory_80cc {
  strings:
    $key_80cc = { d7 be [2] e5 9c [2] e3 a9 [2] cd a9 [2] f2 b5 }

  condition:
    any of them
}