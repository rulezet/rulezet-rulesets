rule TTP_XOR_WriteProcessMemory_6f7b {
  strings:
    $key_6f7b = { 38 09 [2] 0a 2b [2] 0c 1e [2] 22 1e [2] 1d 02 }

  condition:
    any of them
}