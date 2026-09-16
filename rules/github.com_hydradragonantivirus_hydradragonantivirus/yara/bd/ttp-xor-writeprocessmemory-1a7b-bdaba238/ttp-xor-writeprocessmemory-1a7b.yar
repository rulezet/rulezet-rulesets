rule TTP_XOR_WriteProcessMemory_1a7b {
  strings:
    $key_1a7b = { 4d 09 [2] 7f 2b [2] 79 1e [2] 57 1e [2] 68 02 }

  condition:
    any of them
}