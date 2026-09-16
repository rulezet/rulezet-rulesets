rule TTP_XOR_WriteProcessMemory_450b {
  strings:
    $key_450b = { 12 79 [2] 20 5b [2] 26 6e [2] 08 6e [2] 37 72 }

  condition:
    any of them
}