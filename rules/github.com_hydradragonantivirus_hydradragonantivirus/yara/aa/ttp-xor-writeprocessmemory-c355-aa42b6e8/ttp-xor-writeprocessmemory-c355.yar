rule TTP_XOR_WriteProcessMemory_c355 {
  strings:
    $key_c355 = { 94 27 [2] a6 05 [2] a0 30 [2] 8e 30 [2] b1 2c }

  condition:
    any of them
}