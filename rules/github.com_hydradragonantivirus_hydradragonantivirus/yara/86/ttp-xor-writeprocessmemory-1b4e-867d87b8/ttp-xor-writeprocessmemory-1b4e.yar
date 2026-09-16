rule TTP_XOR_WriteProcessMemory_1b4e {
  strings:
    $key_1b4e = { 4c 3c [2] 7e 1e [2] 78 2b [2] 56 2b [2] 69 37 }

  condition:
    any of them
}