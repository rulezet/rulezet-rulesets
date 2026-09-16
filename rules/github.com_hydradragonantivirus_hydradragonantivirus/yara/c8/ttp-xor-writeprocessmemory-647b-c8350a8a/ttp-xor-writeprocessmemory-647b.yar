rule TTP_XOR_WriteProcessMemory_647b {
  strings:
    $key_647b = { 33 09 [2] 01 2b [2] 07 1e [2] 29 1e [2] 16 02 }

  condition:
    any of them
}