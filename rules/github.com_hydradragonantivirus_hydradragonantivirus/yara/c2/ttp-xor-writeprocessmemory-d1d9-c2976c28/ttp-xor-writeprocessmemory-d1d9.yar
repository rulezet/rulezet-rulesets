rule TTP_XOR_WriteProcessMemory_d1d9 {
  strings:
    $key_d1d9 = { 86 ab [2] b4 89 [2] b2 bc [2] 9c bc [2] a3 a0 }

  condition:
    any of them
}