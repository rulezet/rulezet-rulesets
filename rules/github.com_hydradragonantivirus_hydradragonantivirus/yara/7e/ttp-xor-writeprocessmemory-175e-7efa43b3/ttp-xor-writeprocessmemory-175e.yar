rule TTP_XOR_WriteProcessMemory_175e {
  strings:
    $key_175e = { 40 2c [2] 72 0e [2] 74 3b [2] 5a 3b [2] 65 27 }

  condition:
    any of them
}