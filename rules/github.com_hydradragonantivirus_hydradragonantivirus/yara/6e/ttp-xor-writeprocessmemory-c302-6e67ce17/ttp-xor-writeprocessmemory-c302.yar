rule TTP_XOR_WriteProcessMemory_c302 {
  strings:
    $key_c302 = { 94 70 [2] a6 52 [2] a0 67 [2] 8e 67 [2] b1 7b }

  condition:
    any of them
}