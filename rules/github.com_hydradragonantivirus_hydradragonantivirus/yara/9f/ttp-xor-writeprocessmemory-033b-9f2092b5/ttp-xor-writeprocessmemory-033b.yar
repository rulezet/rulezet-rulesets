rule TTP_XOR_WriteProcessMemory_033b {
  strings:
    $key_033b = { 54 49 [2] 66 6b [2] 60 5e [2] 4e 5e [2] 71 42 }

  condition:
    any of them
}