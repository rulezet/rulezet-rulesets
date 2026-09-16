rule TTP_XOR_WriteProcessMemory_c0d2 {
  strings:
    $key_c0d2 = { 97 a0 [2] a5 82 [2] a3 b7 [2] 8d b7 [2] b2 ab }

  condition:
    any of them
}