rule TTP_XOR_WriteProcessMemory_b2cc {
  strings:
    $key_b2cc = { e5 be [2] d7 9c [2] d1 a9 [2] ff a9 [2] c0 b5 }

  condition:
    any of them
}