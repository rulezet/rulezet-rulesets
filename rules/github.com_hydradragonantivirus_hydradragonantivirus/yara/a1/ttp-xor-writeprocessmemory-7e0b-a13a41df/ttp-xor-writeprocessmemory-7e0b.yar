rule TTP_XOR_WriteProcessMemory_7e0b {
  strings:
    $key_7e0b = { 29 79 [2] 1b 5b [2] 1d 6e [2] 33 6e [2] 0c 72 }

  condition:
    any of them
}