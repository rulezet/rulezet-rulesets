rule TTP_XOR_WriteProcessMemory_1c4e {
  strings:
    $key_1c4e = { 4b 3c [2] 79 1e [2] 7f 2b [2] 51 2b [2] 6e 37 }

  condition:
    any of them
}