rule TTP_XOR_WriteProcessMemory_5fa5 {
  strings:
    $key_5fa5 = { 08 d7 [2] 3a f5 [2] 3c c0 [2] 12 c0 [2] 2d dc }

  condition:
    any of them
}