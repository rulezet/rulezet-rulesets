rule TTP_XOR_WriteProcessMemory_599c {
  strings:
    $key_599c = { 0e ee [2] 3c cc [2] 3a f9 [2] 14 f9 [2] 2b e5 }

  condition:
    any of them
}