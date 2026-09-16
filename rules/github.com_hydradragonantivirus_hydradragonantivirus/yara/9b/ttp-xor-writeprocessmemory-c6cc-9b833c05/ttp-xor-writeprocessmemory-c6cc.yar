rule TTP_XOR_WriteProcessMemory_c6cc {
  strings:
    $key_c6cc = { 91 be [2] a3 9c [2] a5 a9 [2] 8b a9 [2] b4 b5 }

  condition:
    any of them
}