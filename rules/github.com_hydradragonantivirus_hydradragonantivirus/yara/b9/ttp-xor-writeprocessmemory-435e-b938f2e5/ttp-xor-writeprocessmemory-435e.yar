rule TTP_XOR_WriteProcessMemory_435e {
  strings:
    $key_435e = { 14 2c [2] 26 0e [2] 20 3b [2] 0e 3b [2] 31 27 }

  condition:
    any of them
}