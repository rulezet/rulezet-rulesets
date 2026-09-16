rule TTP_XOR_WriteProcessMemory_1b0b {
  strings:
    $key_1b0b = { 4c 79 [2] 7e 5b [2] 78 6e [2] 56 6e [2] 69 72 }

  condition:
    any of them
}