rule TTP_XOR_WriteProcessMemory_370b {
  strings:
    $key_370b = { 60 79 [2] 52 5b [2] 54 6e [2] 7a 6e [2] 45 72 }

  condition:
    any of them
}