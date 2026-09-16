rule TTP_XOR_WriteProcessMemory_7f7b {
  strings:
    $key_7f7b = { 28 09 [2] 1a 2b [2] 1c 1e [2] 32 1e [2] 0d 02 }

  condition:
    any of them
}