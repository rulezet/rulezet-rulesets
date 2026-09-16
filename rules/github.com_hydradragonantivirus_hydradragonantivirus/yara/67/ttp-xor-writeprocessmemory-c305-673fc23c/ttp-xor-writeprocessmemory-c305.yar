rule TTP_XOR_WriteProcessMemory_c305 {
  strings:
    $key_c305 = { 94 77 [2] a6 55 [2] a0 60 [2] 8e 60 [2] b1 7c }

  condition:
    any of them
}