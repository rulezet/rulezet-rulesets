rule TTP_XOR_WriteProcessMemory_5da1 {
  strings:
    $key_5da1 = { 0a d3 [2] 38 f1 [2] 3e c4 [2] 10 c4 [2] 2f d8 }

  condition:
    any of them
}