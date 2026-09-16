rule TTP_XOR_WriteProcessMemory_4a4e {
  strings:
    $key_4a4e = { 1d 3c [2] 2f 1e [2] 29 2b [2] 07 2b [2] 38 37 }

  condition:
    any of them
}