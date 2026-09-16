rule TTP_XOR_WriteProcessMemory_c3f2 {
  strings:
    $key_c3f2 = { 94 80 [2] a6 a2 [2] a0 97 [2] 8e 97 [2] b1 8b }

  condition:
    any of them
}