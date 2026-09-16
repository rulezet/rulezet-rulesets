rule TTP_XOR_WriteProcessMemory_7fa1 {
  strings:
    $key_7fa1 = { 28 d3 [2] 1a f1 [2] 1c c4 [2] 32 c4 [2] 0d d8 }

  condition:
    any of them
}