rule TTP_XOR_WriteProcessMemory_454e {
  strings:
    $key_454e = { 12 3c [2] 20 1e [2] 26 2b [2] 08 2b [2] 37 37 }

  condition:
    any of them
}