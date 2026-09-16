rule TTP_XOR_WriteProcessMemory_f7cc {
  strings:
    $key_f7cc = { a0 be [2] 92 9c [2] 94 a9 [2] ba a9 [2] 85 b5 }

  condition:
    any of them
}