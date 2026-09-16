rule TTP_XOR_WriteProcessMemory_166b {
  strings:
    $key_166b = { 41 19 [2] 73 3b [2] 75 0e [2] 5b 0e [2] 64 12 }

  condition:
    any of them
}