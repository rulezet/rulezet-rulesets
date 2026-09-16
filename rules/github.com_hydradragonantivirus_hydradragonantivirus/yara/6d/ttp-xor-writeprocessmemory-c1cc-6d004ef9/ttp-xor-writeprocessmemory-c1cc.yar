rule TTP_XOR_WriteProcessMemory_c1cc {
  strings:
    $key_c1cc = { 96 be [2] a4 9c [2] a2 a9 [2] 8c a9 [2] b3 b5 }

  condition:
    any of them
}