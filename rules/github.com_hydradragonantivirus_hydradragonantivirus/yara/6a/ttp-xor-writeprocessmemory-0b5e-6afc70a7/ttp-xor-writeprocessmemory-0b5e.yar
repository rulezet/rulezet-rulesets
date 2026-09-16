rule TTP_XOR_WriteProcessMemory_0b5e {
  strings:
    $key_0b5e = { 5c 2c [2] 6e 0e [2] 68 3b [2] 46 3b [2] 79 27 }

  condition:
    any of them
}