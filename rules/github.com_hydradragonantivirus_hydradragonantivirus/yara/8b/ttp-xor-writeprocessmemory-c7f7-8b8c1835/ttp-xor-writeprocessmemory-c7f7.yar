rule TTP_XOR_WriteProcessMemory_c7f7 {
  strings:
    $key_c7f7 = { 90 85 [2] a2 a7 [2] a4 92 [2] 8a 92 [2] b5 8e }

  condition:
    any of them
}