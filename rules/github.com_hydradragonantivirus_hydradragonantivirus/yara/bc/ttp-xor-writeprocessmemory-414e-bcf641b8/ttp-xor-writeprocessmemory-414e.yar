rule TTP_XOR_WriteProcessMemory_414e {
  strings:
    $key_414e = { 16 3c [2] 24 1e [2] 22 2b [2] 0c 2b [2] 33 37 }

  condition:
    any of them
}