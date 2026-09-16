rule TTP_XOR_WriteProcessMemory_340b {
  strings:
    $key_340b = { 63 79 [2] 51 5b [2] 57 6e [2] 79 6e [2] 46 72 }

  condition:
    any of them
}