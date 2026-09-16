rule TTP_XOR_WriteProcessMemory_c7d0 {
  strings:
    $key_c7d0 = { 90 a2 [2] a2 80 [2] a4 b5 [2] 8a b5 [2] b5 a9 }

  condition:
    any of them
}