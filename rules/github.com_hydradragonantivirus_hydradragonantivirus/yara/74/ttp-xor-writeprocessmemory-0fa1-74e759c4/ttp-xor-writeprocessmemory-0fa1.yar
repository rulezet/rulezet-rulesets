rule TTP_XOR_WriteProcessMemory_0fa1 {
  strings:
    $key_0fa1 = { 58 d3 [2] 6a f1 [2] 6c c4 [2] 42 c4 [2] 7d d8 }

  condition:
    any of them
}