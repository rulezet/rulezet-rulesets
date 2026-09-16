rule TTP_XOR_WriteProcessMemory_7fa5 {
  strings:
    $key_7fa5 = { 28 d7 [2] 1a f5 [2] 1c c0 [2] 32 c0 [2] 0d dc }

  condition:
    any of them
}