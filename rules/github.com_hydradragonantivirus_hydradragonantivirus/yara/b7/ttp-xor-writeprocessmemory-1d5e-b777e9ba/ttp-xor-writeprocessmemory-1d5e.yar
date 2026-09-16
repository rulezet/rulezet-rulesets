rule TTP_XOR_WriteProcessMemory_1d5e {
  strings:
    $key_1d5e = { 4a 2c [2] 78 0e [2] 7e 3b [2] 50 3b [2] 6f 27 }

  condition:
    any of them
}