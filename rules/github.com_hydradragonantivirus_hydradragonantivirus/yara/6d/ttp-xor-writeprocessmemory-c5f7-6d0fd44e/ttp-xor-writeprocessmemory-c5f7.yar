rule TTP_XOR_WriteProcessMemory_c5f7 {
  strings:
    $key_c5f7 = { 92 85 [2] a0 a7 [2] a6 92 [2] 88 92 [2] b7 8e }

  condition:
    any of them
}