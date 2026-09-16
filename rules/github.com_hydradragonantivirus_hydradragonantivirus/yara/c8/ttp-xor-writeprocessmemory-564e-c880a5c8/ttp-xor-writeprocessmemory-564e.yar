rule TTP_XOR_WriteProcessMemory_564e {
  strings:
    $key_564e = { 01 3c [2] 33 1e [2] 35 2b [2] 1b 2b [2] 24 37 }

  condition:
    any of them
}