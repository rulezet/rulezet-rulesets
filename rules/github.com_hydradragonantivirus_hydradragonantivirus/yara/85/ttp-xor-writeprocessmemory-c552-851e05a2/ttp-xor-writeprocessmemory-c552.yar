rule TTP_XOR_WriteProcessMemory_c552 {
  strings:
    $key_c552 = { 92 20 [2] a0 02 [2] a6 37 [2] 88 37 [2] b7 2b }

  condition:
    any of them
}