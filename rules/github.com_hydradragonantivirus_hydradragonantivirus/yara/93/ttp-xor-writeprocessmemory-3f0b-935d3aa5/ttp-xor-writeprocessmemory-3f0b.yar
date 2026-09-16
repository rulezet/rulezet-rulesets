rule TTP_XOR_WriteProcessMemory_3f0b {
  strings:
    $key_3f0b = { 68 79 [2] 5a 5b [2] 5c 6e [2] 72 6e [2] 4d 72 }

  condition:
    any of them
}