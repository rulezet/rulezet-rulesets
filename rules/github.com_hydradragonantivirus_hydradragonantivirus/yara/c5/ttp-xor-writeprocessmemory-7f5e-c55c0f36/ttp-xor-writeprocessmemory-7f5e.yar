rule TTP_XOR_WriteProcessMemory_7f5e {
  strings:
    $key_7f5e = { 28 2c [2] 1a 0e [2] 1c 3b [2] 32 3b [2] 0d 27 }

  condition:
    any of them
}