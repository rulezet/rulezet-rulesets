rule TTP_XOR_WriteProcessMemory_4d4e {
  strings:
    $key_4d4e = { 1a 3c [2] 28 1e [2] 2e 2b [2] 00 2b [2] 3f 37 }

  condition:
    any of them
}