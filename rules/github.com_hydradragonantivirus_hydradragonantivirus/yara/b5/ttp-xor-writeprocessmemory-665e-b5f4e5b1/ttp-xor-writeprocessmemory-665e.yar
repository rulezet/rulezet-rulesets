rule TTP_XOR_WriteProcessMemory_665e {
  strings:
    $key_665e = { 31 2c [2] 03 0e [2] 05 3b [2] 2b 3b [2] 14 27 }

  condition:
    any of them
}