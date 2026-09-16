rule TTP_XOR_WriteProcessMemory_507b {
  strings:
    $key_507b = { 07 09 [2] 35 2b [2] 33 1e [2] 1d 1e [2] 22 02 }

  condition:
    any of them
}