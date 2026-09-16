rule TTP_XOR_WriteProcessMemory_692e {
  strings:
    $key_692e = { 3e 5c [2] 0c 7e [2] 0a 4b [2] 24 4b [2] 1b 57 }

  condition:
    any of them
}