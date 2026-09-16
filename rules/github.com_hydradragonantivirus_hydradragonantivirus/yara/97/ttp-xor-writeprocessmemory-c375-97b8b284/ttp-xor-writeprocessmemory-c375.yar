rule TTP_XOR_WriteProcessMemory_c375 {
  strings:
    $key_c375 = { 94 07 [2] a6 25 [2] a0 10 [2] 8e 10 [2] b1 0c }

  condition:
    any of them
}