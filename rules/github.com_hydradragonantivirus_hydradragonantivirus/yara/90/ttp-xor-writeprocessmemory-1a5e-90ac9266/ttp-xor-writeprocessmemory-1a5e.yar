rule TTP_XOR_WriteProcessMemory_1a5e {
  strings:
    $key_1a5e = { 4d 2c [2] 7f 0e [2] 79 3b [2] 57 3b [2] 68 27 }

  condition:
    any of them
}