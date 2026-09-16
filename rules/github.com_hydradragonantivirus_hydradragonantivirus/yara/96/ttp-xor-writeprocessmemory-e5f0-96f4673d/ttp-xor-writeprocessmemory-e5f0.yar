rule TTP_XOR_WriteProcessMemory_e5f0 {
  strings:
    $key_e5f0 = { b2 82 [2] 80 a0 [2] 86 95 [2] a8 95 [2] 97 89 }

  condition:
    any of them
}