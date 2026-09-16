rule TTP_XOR_WriteProcessMemory_746b {
  strings:
    $key_746b = { 23 19 [2] 11 3b [2] 17 0e [2] 39 0e [2] 06 12 }

  condition:
    any of them
}