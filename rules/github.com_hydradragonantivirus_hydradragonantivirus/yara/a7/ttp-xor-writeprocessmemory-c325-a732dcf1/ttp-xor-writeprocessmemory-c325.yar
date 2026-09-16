rule TTP_XOR_WriteProcessMemory_c325 {
  strings:
    $key_c325 = { 94 57 [2] a6 75 [2] a0 40 [2] 8e 40 [2] b1 5c }

  condition:
    any of them
}