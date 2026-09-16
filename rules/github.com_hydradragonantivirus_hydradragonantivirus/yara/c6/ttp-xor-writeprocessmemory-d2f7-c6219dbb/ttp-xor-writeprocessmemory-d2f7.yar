rule TTP_XOR_WriteProcessMemory_d2f7 {
  strings:
    $key_d2f7 = { 85 85 [2] b7 a7 [2] b1 92 [2] 9f 92 [2] a0 8e }

  condition:
    any of them
}