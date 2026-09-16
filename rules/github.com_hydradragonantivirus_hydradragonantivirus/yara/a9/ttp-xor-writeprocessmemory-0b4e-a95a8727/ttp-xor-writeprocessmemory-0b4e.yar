rule TTP_XOR_WriteProcessMemory_0b4e {
  strings:
    $key_0b4e = { 5c 3c [2] 6e 1e [2] 68 2b [2] 46 2b [2] 79 37 }

  condition:
    any of them
}