rule TTP_XOR_WriteProcessMemory_08a1 {
  strings:
    $key_08a1 = { 5f d3 [2] 6d f1 [2] 6b c4 [2] 45 c4 [2] 7a d8 }

  condition:
    any of them
}