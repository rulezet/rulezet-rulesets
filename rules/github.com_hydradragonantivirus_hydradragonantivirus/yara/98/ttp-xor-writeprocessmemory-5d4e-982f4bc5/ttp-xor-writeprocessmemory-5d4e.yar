rule TTP_XOR_WriteProcessMemory_5d4e {
  strings:
    $key_5d4e = { 0a 3c [2] 38 1e [2] 3e 2b [2] 10 2b [2] 2f 37 }

  condition:
    any of them
}