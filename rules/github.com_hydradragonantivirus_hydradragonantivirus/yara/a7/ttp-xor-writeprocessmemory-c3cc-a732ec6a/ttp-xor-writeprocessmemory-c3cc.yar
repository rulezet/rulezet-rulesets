rule TTP_XOR_WriteProcessMemory_c3cc {
  strings:
    $key_c3cc = { 94 be [2] a6 9c [2] a0 a9 [2] 8e a9 [2] b1 b5 }

  condition:
    any of them
}