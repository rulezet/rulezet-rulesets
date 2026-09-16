rule TTP_XOR_WriteProcessMemory_7e2e {
  strings:
    $key_7e2e = { 29 5c [2] 1b 7e [2] 1d 4b [2] 33 4b [2] 0c 57 }

  condition:
    any of them
}