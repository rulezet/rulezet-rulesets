rule TTP_XOR_WriteProcessMemory_114e {
  strings:
    $key_114e = { 46 3c [2] 74 1e [2] 72 2b [2] 5c 2b [2] 63 37 }

  condition:
    any of them
}