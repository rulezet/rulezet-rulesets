rule TTP_XOR_WriteProcessMemory_375e {
  strings:
    $key_375e = { 60 2c [2] 52 0e [2] 54 3b [2] 7a 3b [2] 45 27 }

  condition:
    any of them
}