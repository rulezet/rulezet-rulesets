rule TTP_XOR_WriteProcessMemory_a7cc {
  strings:
    $key_a7cc = { f0 be [2] c2 9c [2] c4 a9 [2] ea a9 [2] d5 b5 }

  condition:
    any of them
}