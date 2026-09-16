rule TTP_XOR_WriteProcessMemory_472e {
  strings:
    $key_472e = { 10 5c [2] 22 7e [2] 24 4b [2] 0a 4b [2] 35 57 }

  condition:
    any of them
}