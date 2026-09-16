rule TTP_XOR_WriteProcessMemory_332e {
  strings:
    $key_332e = { 64 5c [2] 56 7e [2] 50 4b [2] 7e 4b [2] 41 57 }

  condition:
    any of them
}