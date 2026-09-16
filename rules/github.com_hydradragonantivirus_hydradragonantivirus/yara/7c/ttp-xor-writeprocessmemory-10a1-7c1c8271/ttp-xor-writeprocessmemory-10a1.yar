rule TTP_XOR_WriteProcessMemory_10a1 {
  strings:
    $key_10a1 = { 47 d3 [2] 75 f1 [2] 73 c4 [2] 5d c4 [2] 62 d8 }

  condition:
    any of them
}