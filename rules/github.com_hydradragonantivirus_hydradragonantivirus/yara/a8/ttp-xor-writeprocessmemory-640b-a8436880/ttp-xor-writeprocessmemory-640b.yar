rule TTP_XOR_WriteProcessMemory_640b {
  strings:
    $key_640b = { 33 79 [2] 01 5b [2] 07 6e [2] 29 6e [2] 16 72 }

  condition:
    any of them
}