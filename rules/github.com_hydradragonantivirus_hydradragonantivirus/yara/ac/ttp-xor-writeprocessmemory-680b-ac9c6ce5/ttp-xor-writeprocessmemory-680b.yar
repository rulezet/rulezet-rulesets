rule TTP_XOR_WriteProcessMemory_680b {
  strings:
    $key_680b = { 3f 79 [2] 0d 5b [2] 0b 6e [2] 25 6e [2] 1a 72 }

  condition:
    any of them
}