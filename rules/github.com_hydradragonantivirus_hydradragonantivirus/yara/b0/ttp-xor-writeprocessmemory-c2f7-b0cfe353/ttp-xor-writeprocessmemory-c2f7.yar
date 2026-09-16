rule TTP_XOR_WriteProcessMemory_c2f7 {
  strings:
    $key_c2f7 = { 95 85 [2] a7 a7 [2] a1 92 [2] 8f 92 [2] b0 8e }

  condition:
    any of them
}