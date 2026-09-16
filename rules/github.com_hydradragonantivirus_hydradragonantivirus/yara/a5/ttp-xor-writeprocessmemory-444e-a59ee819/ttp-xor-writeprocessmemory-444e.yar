rule TTP_XOR_WriteProcessMemory_444e {
  strings:
    $key_444e = { 13 3c [2] 21 1e [2] 27 2b [2] 09 2b [2] 36 37 }

  condition:
    any of them
}