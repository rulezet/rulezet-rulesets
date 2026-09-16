rule TTP_XOR_WriteProcessMemory_565e {
  strings:
    $key_565e = { 01 2c [2] 33 0e [2] 35 3b [2] 1b 3b [2] 24 27 }

  condition:
    any of them
}