rule TTP_XOR_WriteProcessMemory_c3f7 {
  strings:
    $key_c3f7 = { 94 85 [2] a6 a7 [2] a0 92 [2] 8e 92 [2] b1 8e }

  condition:
    any of them
}