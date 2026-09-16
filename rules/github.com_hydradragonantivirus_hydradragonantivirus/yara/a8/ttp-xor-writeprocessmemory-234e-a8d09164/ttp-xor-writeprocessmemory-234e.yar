rule TTP_XOR_WriteProcessMemory_234e {
  strings:
    $key_234e = { 74 3c [2] 46 1e [2] 40 2b [2] 6e 2b [2] 51 37 }

  condition:
    any of them
}