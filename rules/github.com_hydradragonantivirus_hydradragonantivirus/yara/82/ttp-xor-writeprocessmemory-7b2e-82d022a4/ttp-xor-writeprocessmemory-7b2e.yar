rule TTP_XOR_WriteProcessMemory_7b2e {
  strings:
    $key_7b2e = { 2c 5c [2] 1e 7e [2] 18 4b [2] 36 4b [2] 09 57 }

  condition:
    any of them
}