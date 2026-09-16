rule TTP_XOR_WriteProcessMemory_7e7b {
  strings:
    $key_7e7b = { 29 09 [2] 1b 2b [2] 1d 1e [2] 33 1e [2] 0c 02 }

  condition:
    any of them
}