rule TTP_XOR_WriteProcessMemory_4b0b {
  strings:
    $key_4b0b = { 1c 79 [2] 2e 5b [2] 28 6e [2] 06 6e [2] 39 72 }

  condition:
    any of them
}