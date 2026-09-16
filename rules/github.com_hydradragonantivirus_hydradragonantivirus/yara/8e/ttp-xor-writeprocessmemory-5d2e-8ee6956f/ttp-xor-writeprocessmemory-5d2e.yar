rule TTP_XOR_WriteProcessMemory_5d2e {
  strings:
    $key_5d2e = { 0a 5c [2] 38 7e [2] 3e 4b [2] 10 4b [2] 2f 57 }

  condition:
    any of them
}