rule TTP_XOR_WriteProcessMemory_5c2e {
  strings:
    $key_5c2e = { 0b 5c [2] 39 7e [2] 3f 4b [2] 11 4b [2] 2e 57 }

  condition:
    any of them
}