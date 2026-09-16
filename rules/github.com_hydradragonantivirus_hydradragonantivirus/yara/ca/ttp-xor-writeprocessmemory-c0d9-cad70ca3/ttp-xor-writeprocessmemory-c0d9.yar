rule TTP_XOR_WriteProcessMemory_c0d9 {
  strings:
    $key_c0d9 = { 97 ab [2] a5 89 [2] a3 bc [2] 8d bc [2] b2 a0 }

  condition:
    any of them
}