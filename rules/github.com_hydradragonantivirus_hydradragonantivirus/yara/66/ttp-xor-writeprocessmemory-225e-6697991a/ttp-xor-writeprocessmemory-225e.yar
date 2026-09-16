rule TTP_XOR_WriteProcessMemory_225e {
  strings:
    $key_225e = { 75 2c [2] 47 0e [2] 41 3b [2] 6f 3b [2] 50 27 }

  condition:
    any of them
}