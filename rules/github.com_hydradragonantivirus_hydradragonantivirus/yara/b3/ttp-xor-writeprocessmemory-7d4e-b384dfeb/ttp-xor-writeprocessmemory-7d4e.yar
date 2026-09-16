rule TTP_XOR_WriteProcessMemory_7d4e {
  strings:
    $key_7d4e = { 2a 3c [2] 18 1e [2] 1e 2b [2] 30 2b [2] 0f 37 }

  condition:
    any of them
}