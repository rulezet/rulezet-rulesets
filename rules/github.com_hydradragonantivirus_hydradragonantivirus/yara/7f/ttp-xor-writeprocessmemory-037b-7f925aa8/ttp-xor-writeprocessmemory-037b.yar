rule TTP_XOR_WriteProcessMemory_037b {
  strings:
    $key_037b = { 54 09 [2] 66 2b [2] 60 1e [2] 4e 1e [2] 71 02 }

  condition:
    any of them
}