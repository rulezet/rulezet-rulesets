rule TTP_XOR_WriteProcessMemory_c5d9 {
  strings:
    $key_c5d9 = { 92 ab [2] a0 89 [2] a6 bc [2] 88 bc [2] b7 a0 }

  condition:
    any of them
}