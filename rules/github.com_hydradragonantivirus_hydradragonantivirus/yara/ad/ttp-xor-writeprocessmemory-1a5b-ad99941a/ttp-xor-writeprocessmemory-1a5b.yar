rule TTP_XOR_WriteProcessMemory_1a5b {
  strings:
    $key_1a5b = { 4d 29 [2] 7f 0b [2] 79 3e [2] 57 3e [2] 68 22 }

  condition:
    any of them
}