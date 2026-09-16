rule TTP_XOR_WriteProcessMemory_5c1e {
  strings:
    $key_5c1e = { 0b 6c [2] 39 4e [2] 3f 7b [2] 11 7b [2] 2e 67 }

  condition:
    any of them
}