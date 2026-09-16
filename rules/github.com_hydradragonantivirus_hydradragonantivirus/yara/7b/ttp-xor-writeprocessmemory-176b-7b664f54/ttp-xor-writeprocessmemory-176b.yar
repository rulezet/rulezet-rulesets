rule TTP_XOR_WriteProcessMemory_176b {
  strings:
    $key_176b = { 40 19 [2] 72 3b [2] 74 0e [2] 5a 0e [2] 65 12 }

  condition:
    any of them
}