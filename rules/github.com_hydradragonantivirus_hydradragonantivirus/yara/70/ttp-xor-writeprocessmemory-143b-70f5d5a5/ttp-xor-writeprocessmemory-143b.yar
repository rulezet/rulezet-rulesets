rule TTP_XOR_WriteProcessMemory_143b {
  strings:
    $key_143b = { 43 49 [2] 71 6b [2] 77 5e [2] 59 5e [2] 66 42 }

  condition:
    any of them
}