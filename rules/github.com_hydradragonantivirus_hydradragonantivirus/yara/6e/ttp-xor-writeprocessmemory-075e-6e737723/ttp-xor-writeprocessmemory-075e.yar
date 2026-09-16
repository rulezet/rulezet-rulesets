rule TTP_XOR_WriteProcessMemory_075e {
  strings:
    $key_075e = { 50 2c [2] 62 0e [2] 64 3b [2] 4a 3b [2] 75 27 }

  condition:
    any of them
}