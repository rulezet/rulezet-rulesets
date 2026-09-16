rule TTP_XOR_WriteProcessMemory_7d2e {
  strings:
    $key_7d2e = { 2a 5c [2] 18 7e [2] 1e 4b [2] 30 4b [2] 0f 57 }

  condition:
    any of them
}