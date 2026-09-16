rule TTP_XOR_WriteProcessMemory_7da1 {
  strings:
    $key_7da1 = { 2a d3 [2] 18 f1 [2] 1e c4 [2] 30 c4 [2] 0f d8 }

  condition:
    any of them
}