rule TTP_XOR_WriteProcessMemory_c7c0 {
  strings:
    $key_c7c0 = { 90 b2 [2] a2 90 [2] a4 a5 [2] 8a a5 [2] b5 b9 }

  condition:
    any of them
}