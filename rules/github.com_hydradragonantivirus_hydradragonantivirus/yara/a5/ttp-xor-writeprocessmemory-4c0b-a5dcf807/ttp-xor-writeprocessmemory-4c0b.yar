rule TTP_XOR_WriteProcessMemory_4c0b {
  strings:
    $key_4c0b = { 1b 79 [2] 29 5b [2] 2f 6e [2] 01 6e [2] 3e 72 }

  condition:
    any of them
}