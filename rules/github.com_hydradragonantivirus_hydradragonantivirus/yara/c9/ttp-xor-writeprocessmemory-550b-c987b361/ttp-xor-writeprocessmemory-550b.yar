rule TTP_XOR_WriteProcessMemory_550b {
  strings:
    $key_550b = { 02 79 [2] 30 5b [2] 36 6e [2] 18 6e [2] 27 72 }

  condition:
    any of them
}