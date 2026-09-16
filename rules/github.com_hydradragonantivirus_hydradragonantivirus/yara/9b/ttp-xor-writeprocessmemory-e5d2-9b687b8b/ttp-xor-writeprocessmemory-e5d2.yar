rule TTP_XOR_WriteProcessMemory_e5d2 {
  strings:
    $key_e5d2 = { b2 a0 [2] 80 82 [2] 86 b7 [2] a8 b7 [2] 97 ab }

  condition:
    any of them
}