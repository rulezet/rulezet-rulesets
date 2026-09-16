rule TTP_XOR_WriteProcessMemory_1d2e {
  strings:
    $key_1d2e = { 4a 5c [2] 78 7e [2] 7e 4b [2] 50 4b [2] 6f 57 }

  condition:
    any of them
}