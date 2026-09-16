rule TTP_XOR_WriteProcessMemory_c300 {
  strings:
    $key_c300 = { 94 72 [2] a6 50 [2] a0 65 [2] 8e 65 [2] b1 79 }

  condition:
    any of them
}