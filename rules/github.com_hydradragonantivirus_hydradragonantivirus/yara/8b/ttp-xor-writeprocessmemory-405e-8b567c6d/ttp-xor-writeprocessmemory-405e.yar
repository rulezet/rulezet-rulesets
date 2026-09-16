rule TTP_XOR_WriteProcessMemory_405e {
  strings:
    $key_405e = { 17 2c [2] 25 0e [2] 23 3b [2] 0d 3b [2] 32 27 }

  condition:
    any of them
}