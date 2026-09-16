rule TTP_XOR_WriteProcessMemory_6e7b {
  strings:
    $key_6e7b = { 39 09 [2] 0b 2b [2] 0d 1e [2] 23 1e [2] 1c 02 }

  condition:
    any of them
}