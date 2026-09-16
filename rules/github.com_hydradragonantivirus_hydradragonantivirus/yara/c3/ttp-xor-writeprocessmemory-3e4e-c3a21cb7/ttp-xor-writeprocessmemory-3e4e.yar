rule TTP_XOR_WriteProcessMemory_3e4e {
  strings:
    $key_3e4e = { 69 3c [2] 5b 1e [2] 5d 2b [2] 73 2b [2] 4c 37 }

  condition:
    any of them
}