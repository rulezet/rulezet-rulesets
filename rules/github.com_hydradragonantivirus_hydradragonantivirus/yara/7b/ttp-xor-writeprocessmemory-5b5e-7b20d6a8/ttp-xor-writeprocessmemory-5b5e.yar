rule TTP_XOR_WriteProcessMemory_5b5e {
  strings:
    $key_5b5e = { 0c 2c [2] 3e 0e [2] 38 3b [2] 16 3b [2] 29 27 }

  condition:
    any of them
}