rule TTP_XOR_WriteProcessMemory_787b {
  strings:
    $key_787b = { 2f 09 [2] 1d 2b [2] 1b 1e [2] 35 1e [2] 0a 02 }

  condition:
    any of them
}