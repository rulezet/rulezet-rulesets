rule TTP_XOR_WriteProcessMemory_c5cc {
  strings:
    $key_c5cc = { 92 be [2] a0 9c [2] a6 a9 [2] 88 a9 [2] b7 b5 }

  condition:
    any of them
}