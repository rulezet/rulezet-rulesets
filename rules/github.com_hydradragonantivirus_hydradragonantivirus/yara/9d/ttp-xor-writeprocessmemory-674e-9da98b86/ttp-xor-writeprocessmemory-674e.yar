rule TTP_XOR_WriteProcessMemory_674e {
  strings:
    $key_674e = { 30 3c [2] 02 1e [2] 04 2b [2] 2a 2b [2] 15 37 }

  condition:
    any of them
}