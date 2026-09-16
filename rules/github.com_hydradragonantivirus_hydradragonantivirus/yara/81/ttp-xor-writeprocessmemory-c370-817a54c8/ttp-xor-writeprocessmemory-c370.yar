rule TTP_XOR_WriteProcessMemory_c370 {
  strings:
    $key_c370 = { 94 02 [2] a6 20 [2] a0 15 [2] 8e 15 [2] b1 09 }

  condition:
    any of them
}