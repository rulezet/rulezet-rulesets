rule TTP_XOR_WriteProcessMemory_6e2e {
  strings:
    $key_6e2e = { 39 5c [2] 0b 7e [2] 0d 4b [2] 23 4b [2] 1c 57 }

  condition:
    any of them
}