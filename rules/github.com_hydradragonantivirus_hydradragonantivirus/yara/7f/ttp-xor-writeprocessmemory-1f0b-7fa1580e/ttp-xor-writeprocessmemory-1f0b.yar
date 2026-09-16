rule TTP_XOR_WriteProcessMemory_1f0b {
  strings:
    $key_1f0b = { 48 79 [2] 7a 5b [2] 7c 6e [2] 52 6e [2] 6d 72 }

  condition:
    any of them
}