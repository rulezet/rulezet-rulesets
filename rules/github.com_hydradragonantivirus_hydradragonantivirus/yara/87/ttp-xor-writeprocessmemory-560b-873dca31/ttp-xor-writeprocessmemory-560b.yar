rule TTP_XOR_WriteProcessMemory_560b {
  strings:
    $key_560b = { 01 79 [2] 33 5b [2] 35 6e [2] 1b 6e [2] 24 72 }

  condition:
    any of them
}