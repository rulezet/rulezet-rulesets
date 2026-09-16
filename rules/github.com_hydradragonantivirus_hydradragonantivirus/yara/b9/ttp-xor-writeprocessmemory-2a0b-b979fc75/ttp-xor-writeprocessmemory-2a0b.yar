rule TTP_XOR_WriteProcessMemory_2a0b {
  strings:
    $key_2a0b = { 7d 79 [2] 4f 5b [2] 49 6e [2] 67 6e [2] 58 72 }

  condition:
    any of them
}