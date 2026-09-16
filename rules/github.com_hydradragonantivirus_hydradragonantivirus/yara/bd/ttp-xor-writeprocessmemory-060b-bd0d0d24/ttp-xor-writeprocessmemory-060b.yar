rule TTP_XOR_WriteProcessMemory_060b {
  strings:
    $key_060b = { 51 79 [2] 63 5b [2] 65 6e [2] 4b 6e [2] 74 72 }

  condition:
    any of them
}