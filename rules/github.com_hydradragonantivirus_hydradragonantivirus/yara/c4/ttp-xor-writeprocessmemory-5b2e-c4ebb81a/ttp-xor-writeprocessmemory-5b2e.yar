rule TTP_XOR_WriteProcessMemory_5b2e {
  strings:
    $key_5b2e = { 0c 5c [2] 3e 7e [2] 38 4b [2] 16 4b [2] 29 57 }

  condition:
    any of them
}