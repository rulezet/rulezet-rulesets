rule TTP_XOR_WriteProcessMemory_4d5e {
  strings:
    $key_4d5e = { 1a 2c [2] 28 0e [2] 2e 3b [2] 00 3b [2] 3f 27 }

  condition:
    any of them
}