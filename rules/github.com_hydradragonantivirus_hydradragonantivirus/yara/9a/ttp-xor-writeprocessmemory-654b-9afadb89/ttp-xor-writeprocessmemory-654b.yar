rule TTP_XOR_WriteProcessMemory_654b {
  strings:
    $key_654b = { 32 39 [2] 00 1b [2] 06 2e [2] 28 2e [2] 17 32 }

  condition:
    any of them
}