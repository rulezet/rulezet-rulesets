rule TTP_XOR_WriteProcessMemory_635e {
  strings:
    $key_635e = { 34 2c [2] 06 0e [2] 00 3b [2] 2e 3b [2] 11 27 }

  condition:
    any of them
}