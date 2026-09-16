rule TTP_XOR_WriteProcessMemory_594e {
  strings:
    $key_594e = { 0e 3c [2] 3c 1e [2] 3a 2b [2] 14 2b [2] 2b 37 }

  condition:
    any of them
}