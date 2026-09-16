rule TTP_XOR_WriteProcessMemory_394e {
  strings:
    $key_394e = { 6e 3c [2] 5c 1e [2] 5a 2b [2] 74 2b [2] 4b 37 }

  condition:
    any of them
}