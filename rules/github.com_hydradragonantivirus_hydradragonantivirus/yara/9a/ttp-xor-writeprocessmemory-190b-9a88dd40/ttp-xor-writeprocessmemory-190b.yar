rule TTP_XOR_WriteProcessMemory_190b {
  strings:
    $key_190b = { 4e 79 [2] 7c 5b [2] 7a 6e [2] 54 6e [2] 6b 72 }

  condition:
    any of them
}