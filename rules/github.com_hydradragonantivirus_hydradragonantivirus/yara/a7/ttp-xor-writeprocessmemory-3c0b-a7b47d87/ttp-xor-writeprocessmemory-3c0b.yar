rule TTP_XOR_WriteProcessMemory_3c0b {
  strings:
    $key_3c0b = { 6b 79 [2] 59 5b [2] 5f 6e [2] 71 6e [2] 4e 72 }

  condition:
    any of them
}