rule TTP_XOR_WriteProcessMemory_447b {
  strings:
    $key_447b = { 13 09 [2] 21 2b [2] 27 1e [2] 09 1e [2] 36 02 }

  condition:
    any of them
}