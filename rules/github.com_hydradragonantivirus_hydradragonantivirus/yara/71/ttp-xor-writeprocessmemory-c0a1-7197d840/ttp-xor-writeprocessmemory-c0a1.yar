rule TTP_XOR_WriteProcessMemory_c0a1 {
  strings:
    $key_c0a1 = { 97 d3 [2] a5 f1 [2] a3 c4 [2] 8d c4 [2] b2 d8 }

  condition:
    any of them
}