rule TTP_XOR_WriteProcessMemory_0fa5 {
  strings:
    $key_0fa5 = { 58 d7 [2] 6a f5 [2] 6c c0 [2] 42 c0 [2] 7d dc }

  condition:
    any of them
}