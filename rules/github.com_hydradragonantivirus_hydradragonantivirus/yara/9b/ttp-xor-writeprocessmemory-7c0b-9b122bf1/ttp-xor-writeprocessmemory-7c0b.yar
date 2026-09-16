rule TTP_XOR_WriteProcessMemory_7c0b {
  strings:
    $key_7c0b = { 2b 79 [2] 19 5b [2] 1f 6e [2] 31 6e [2] 0e 72 }

  condition:
    any of them
}