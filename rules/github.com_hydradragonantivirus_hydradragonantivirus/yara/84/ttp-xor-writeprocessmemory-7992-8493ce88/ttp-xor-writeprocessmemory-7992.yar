rule TTP_XOR_WriteProcessMemory_7992 {
  strings:
    $key_7992 = { 2e e0 [2] 1c c2 [2] 1a f7 [2] 34 f7 [2] 0b eb }

  condition:
    any of them
}