rule TTP_XOR_WriteProcessMemory_355e {
  strings:
    $key_355e = { 62 2c [2] 50 0e [2] 56 3b [2] 78 3b [2] 47 27 }

  condition:
    any of them
}