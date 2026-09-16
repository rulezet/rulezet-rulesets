rule TTP_XOR_WriteProcessMemory_e9cc {
  strings:
    $key_e9cc = { be be [2] 8c 9c [2] 8a a9 [2] a4 a9 [2] 9b b5 }

  condition:
    any of them
}