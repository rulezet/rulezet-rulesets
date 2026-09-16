rule TTP_XOR_WriteProcessMemory_115e {
  strings:
    $key_115e = { 46 2c [2] 74 0e [2] 72 3b [2] 5c 3b [2] 63 27 }

  condition:
    any of them
}