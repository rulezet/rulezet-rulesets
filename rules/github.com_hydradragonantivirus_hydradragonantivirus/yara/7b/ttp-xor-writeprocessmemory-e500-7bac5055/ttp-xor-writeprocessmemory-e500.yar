rule TTP_XOR_WriteProcessMemory_e500 {
  strings:
    $key_e500 = { b2 72 [2] 80 50 [2] 86 65 [2] a8 65 [2] 97 79 }

  condition:
    any of them
}