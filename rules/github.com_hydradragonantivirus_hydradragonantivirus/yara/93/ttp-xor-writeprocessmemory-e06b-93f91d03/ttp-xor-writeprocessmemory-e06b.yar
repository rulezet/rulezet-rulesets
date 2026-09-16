rule TTP_XOR_WriteProcessMemory_e06b {
  strings:
    $key_e06b = { b7 19 [2] 85 3b [2] 83 0e [2] ad 0e [2] 92 12 }

  condition:
    any of them
}