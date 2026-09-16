rule TTP_XOR_WriteProcessMemory_daa1 {
  strings:
    $key_daa1 = { 8d d3 [2] bf f1 [2] b9 c4 [2] 97 c4 [2] a8 d8 }

  condition:
    any of them
}