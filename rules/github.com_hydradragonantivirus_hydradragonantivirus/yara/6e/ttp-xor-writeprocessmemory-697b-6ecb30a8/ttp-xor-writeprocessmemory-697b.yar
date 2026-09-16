rule TTP_XOR_WriteProcessMemory_697b {
  strings:
    $key_697b = { 3e 09 [2] 0c 2b [2] 0a 1e [2] 24 1e [2] 1b 02 }

  condition:
    any of them
}