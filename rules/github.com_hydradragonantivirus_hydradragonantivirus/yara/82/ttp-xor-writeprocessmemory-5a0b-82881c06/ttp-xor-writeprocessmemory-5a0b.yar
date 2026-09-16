rule TTP_XOR_WriteProcessMemory_5a0b {
  strings:
    $key_5a0b = { 0d 79 [2] 3f 5b [2] 39 6e [2] 17 6e [2] 28 72 }

  condition:
    any of them
}