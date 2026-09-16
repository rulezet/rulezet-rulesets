rule TTP_XOR_WriteProcessMemory_5b7b {
  strings:
    $key_5b7b = { 0c 09 [2] 3e 2b [2] 38 1e [2] 16 1e [2] 29 02 }

  condition:
    any of them
}