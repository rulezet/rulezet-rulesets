rule TTP_XOR_WriteProcessMemory_597b {
  strings:
    $key_597b = { 0e 09 [2] 3c 2b [2] 3a 1e [2] 14 1e [2] 2b 02 }

  condition:
    any of them
}