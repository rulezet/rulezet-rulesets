rule TTP_XOR_WriteProcessMemory_7e4e {
  strings:
    $key_7e4e = { 29 3c [2] 1b 1e [2] 1d 2b [2] 33 2b [2] 0c 37 }

  condition:
    any of them
}