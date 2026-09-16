rule TTP_XOR_WriteProcessMemory_b4cc {
  strings:
    $key_b4cc = { e3 be [2] d1 9c [2] d7 a9 [2] f9 a9 [2] c6 b5 }

  condition:
    any of them
}