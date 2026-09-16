rule TTP_XOR_WriteProcessMemory_38a1 {
  strings:
    $key_38a1 = { 6f d3 [2] 5d f1 [2] 5b c4 [2] 75 c4 [2] 4a d8 }

  condition:
    any of them
}