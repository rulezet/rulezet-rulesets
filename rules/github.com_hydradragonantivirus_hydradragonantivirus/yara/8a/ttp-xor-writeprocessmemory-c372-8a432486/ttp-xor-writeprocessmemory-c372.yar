rule TTP_XOR_WriteProcessMemory_c372 {
  strings:
    $key_c372 = { 94 00 [2] a6 22 [2] a0 17 [2] 8e 17 [2] b1 0b }

  condition:
    any of them
}