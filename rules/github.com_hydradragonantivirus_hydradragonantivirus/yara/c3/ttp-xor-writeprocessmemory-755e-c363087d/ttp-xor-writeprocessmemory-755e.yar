rule TTP_XOR_WriteProcessMemory_755e {
  strings:
    $key_755e = { 22 2c [2] 10 0e [2] 16 3b [2] 38 3b [2] 07 27 }

  condition:
    any of them
}