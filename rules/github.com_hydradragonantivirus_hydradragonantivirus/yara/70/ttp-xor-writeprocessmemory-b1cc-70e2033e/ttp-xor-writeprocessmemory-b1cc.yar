rule TTP_XOR_WriteProcessMemory_b1cc {
  strings:
    $key_b1cc = { e6 be [2] d4 9c [2] d2 a9 [2] fc a9 [2] c3 b5 }

  condition:
    any of them
}