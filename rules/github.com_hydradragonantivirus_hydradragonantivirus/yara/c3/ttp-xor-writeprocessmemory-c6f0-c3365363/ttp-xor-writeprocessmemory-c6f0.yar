rule TTP_XOR_WriteProcessMemory_c6f0 {
  strings:
    $key_c6f0 = { 91 82 [2] a3 a0 [2] a5 95 [2] 8b 95 [2] b4 89 }

  condition:
    any of them
}