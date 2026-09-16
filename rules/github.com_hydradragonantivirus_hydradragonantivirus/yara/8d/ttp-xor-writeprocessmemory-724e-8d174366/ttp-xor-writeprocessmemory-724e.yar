rule TTP_XOR_WriteProcessMemory_724e {
  strings:
    $key_724e = { 25 3c [2] 17 1e [2] 11 2b [2] 3f 2b [2] 00 37 }

  condition:
    any of them
}