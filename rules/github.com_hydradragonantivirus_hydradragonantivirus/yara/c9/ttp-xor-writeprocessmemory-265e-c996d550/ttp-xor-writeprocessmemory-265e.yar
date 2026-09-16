rule TTP_XOR_WriteProcessMemory_265e {
  strings:
    $key_265e = { 71 2c [2] 43 0e [2] 45 3b [2] 6b 3b [2] 54 27 }

  condition:
    any of them
}