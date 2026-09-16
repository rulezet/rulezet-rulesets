rule TTP_XOR_WriteProcessMemory_334e {
  strings:
    $key_334e = { 64 3c [2] 56 1e [2] 50 2b [2] 7e 2b [2] 41 37 }

  condition:
    any of them
}