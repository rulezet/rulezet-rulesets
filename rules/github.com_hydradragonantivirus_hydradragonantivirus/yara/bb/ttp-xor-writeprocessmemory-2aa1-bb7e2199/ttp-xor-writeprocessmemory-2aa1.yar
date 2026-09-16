rule TTP_XOR_WriteProcessMemory_2aa1 {
  strings:
    $key_2aa1 = { 7d d3 [2] 4f f1 [2] 49 c4 [2] 67 c4 [2] 58 d8 }

  condition:
    any of them
}