rule TTP_XOR_WriteProcessMemory_7e4b {
  strings:
    $key_7e4b = { 29 39 [2] 1b 1b [2] 1d 2e [2] 33 2e [2] 0c 32 }

  condition:
    any of them
}