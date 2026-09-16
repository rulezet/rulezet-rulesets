rule TTP_XOR_WriteProcessMemory_4aa1 {
  strings:
    $key_4aa1 = { 1d d3 [2] 2f f1 [2] 29 c4 [2] 07 c4 [2] 38 d8 }

  condition:
    any of them
}