rule TTP_XOR_WriteProcessMemory_1c6b {
  strings:
    $key_1c6b = { 4b 19 [2] 79 3b [2] 7f 0e [2] 51 0e [2] 6e 12 }

  condition:
    any of them
}