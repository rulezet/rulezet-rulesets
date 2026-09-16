rule TTP_XOR_WriteProcessMemory_3da1 {
  strings:
    $key_3da1 = { 6a d3 [2] 58 f1 [2] 5e c4 [2] 70 c4 [2] 4f d8 }

  condition:
    any of them
}