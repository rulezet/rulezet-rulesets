rule TTP_XOR_WriteProcessMemory_cba1 {
  strings:
    $key_cba1 = { 9c d3 [2] ae f1 [2] a8 c4 [2] 86 c4 [2] b9 d8 }

  condition:
    any of them
}