rule TTP_XOR_WriteProcessMemory_5c3e {
  strings:
    $key_5c3e = { 0b 4c [2] 39 6e [2] 3f 5b [2] 11 5b [2] 2e 47 }

  condition:
    any of them
}