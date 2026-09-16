rule TTP_XOR_WriteProcessMemory_537b {
  strings:
    $key_537b = { 04 09 [2] 36 2b [2] 30 1e [2] 1e 1e [2] 21 02 }

  condition:
    any of them
}