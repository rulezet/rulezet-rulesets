rule TTP_XOR_WriteProcessMemory_1aa1 {
  strings:
    $key_1aa1 = { 4d d3 [2] 7f f1 [2] 79 c4 [2] 57 c4 [2] 68 d8 }

  condition:
    any of them
}