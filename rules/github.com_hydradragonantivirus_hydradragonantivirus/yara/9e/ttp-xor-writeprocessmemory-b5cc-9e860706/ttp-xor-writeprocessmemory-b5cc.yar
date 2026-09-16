rule TTP_XOR_WriteProcessMemory_b5cc {
  strings:
    $key_b5cc = { e2 be [2] d0 9c [2] d6 a9 [2] f8 a9 [2] c7 b5 }

  condition:
    any of them
}