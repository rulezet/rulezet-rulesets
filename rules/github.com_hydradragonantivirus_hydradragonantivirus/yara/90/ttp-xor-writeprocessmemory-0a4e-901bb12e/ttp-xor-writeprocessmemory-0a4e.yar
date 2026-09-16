rule TTP_XOR_WriteProcessMemory_0a4e {
  strings:
    $key_0a4e = { 5d 3c [2] 6f 1e [2] 69 2b [2] 47 2b [2] 78 37 }

  condition:
    any of them
}