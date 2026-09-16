rule TTP_XOR_WriteProcessMemory_5d7b {
  strings:
    $key_5d7b = { 0a 09 [2] 38 2b [2] 3e 1e [2] 10 1e [2] 2f 02 }

  condition:
    any of them
}