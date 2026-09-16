rule TTP_XOR_WriteProcessMemory_c6c0 {
  strings:
    $key_c6c0 = { 91 b2 [2] a3 90 [2] a5 a5 [2] 8b a5 [2] b4 b9 }

  condition:
    any of them
}