rule TTP_XOR_WriteProcessMemory_637b {
  strings:
    $key_637b = { 34 09 [2] 06 2b [2] 00 1e [2] 2e 1e [2] 11 02 }

  condition:
    any of them
}