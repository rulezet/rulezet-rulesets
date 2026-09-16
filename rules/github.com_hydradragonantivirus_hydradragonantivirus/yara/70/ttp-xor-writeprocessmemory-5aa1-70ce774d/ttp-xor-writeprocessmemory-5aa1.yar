rule TTP_XOR_WriteProcessMemory_5aa1 {
  strings:
    $key_5aa1 = { 0d d3 [2] 3f f1 [2] 39 c4 [2] 17 c4 [2] 28 d8 }

  condition:
    any of them
}