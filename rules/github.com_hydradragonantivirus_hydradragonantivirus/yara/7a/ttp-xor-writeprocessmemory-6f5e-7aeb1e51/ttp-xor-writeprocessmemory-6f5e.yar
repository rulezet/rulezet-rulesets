rule TTP_XOR_WriteProcessMemory_6f5e {
  strings:
    $key_6f5e = { 38 2c [2] 0a 0e [2] 0c 3b [2] 22 3b [2] 1d 27 }

  condition:
    any of them
}