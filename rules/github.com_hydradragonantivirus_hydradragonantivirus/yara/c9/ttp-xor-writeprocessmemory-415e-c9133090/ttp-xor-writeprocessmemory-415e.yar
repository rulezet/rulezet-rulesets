rule TTP_XOR_WriteProcessMemory_415e {
  strings:
    $key_415e = { 16 2c [2] 24 0e [2] 22 3b [2] 0c 3b [2] 33 27 }

  condition:
    any of them
}