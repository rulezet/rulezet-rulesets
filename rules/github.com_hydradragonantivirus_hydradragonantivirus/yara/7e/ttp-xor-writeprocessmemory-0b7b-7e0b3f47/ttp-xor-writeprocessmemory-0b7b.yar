rule TTP_XOR_WriteProcessMemory_0b7b {
  strings:
    $key_0b7b = { 5c 09 [2] 6e 2b [2] 68 1e [2] 46 1e [2] 79 02 }

  condition:
    any of them
}