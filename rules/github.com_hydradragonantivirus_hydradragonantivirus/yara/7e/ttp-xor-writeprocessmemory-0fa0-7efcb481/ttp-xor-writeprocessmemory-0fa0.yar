rule TTP_XOR_WriteProcessMemory_0fa0 {
  strings:
    $key_0fa0 = { 58 d2 [2] 6a f0 [2] 6c c5 [2] 42 c5 [2] 7d d9 }

  condition:
    any of them
}