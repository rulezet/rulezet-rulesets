rule TTP_XOR_WriteProcessMemory_304e {
  strings:
    $key_304e = { 67 3c [2] 55 1e [2] 53 2b [2] 7d 2b [2] 42 37 }

  condition:
    any of them
}