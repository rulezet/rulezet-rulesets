rule TTP_XOR_WriteProcessMemory_677b {
  strings:
    $key_677b = { 30 09 [2] 02 2b [2] 04 1e [2] 2a 1e [2] 15 02 }

  condition:
    any of them
}