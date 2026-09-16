rule TTP_XOR_WriteProcessMemory_2ba1 {
  strings:
    $key_2ba1 = { 7c d3 [2] 4e f1 [2] 48 c4 [2] 66 c4 [2] 59 d8 }

  condition:
    any of them
}