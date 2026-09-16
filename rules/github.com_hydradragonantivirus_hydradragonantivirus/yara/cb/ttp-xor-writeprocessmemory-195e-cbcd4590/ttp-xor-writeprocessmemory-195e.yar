rule TTP_XOR_WriteProcessMemory_195e {
  strings:
    $key_195e = { 4e 2c [2] 7c 0e [2] 7a 3b [2] 54 3b [2] 6b 27 }

  condition:
    any of them
}