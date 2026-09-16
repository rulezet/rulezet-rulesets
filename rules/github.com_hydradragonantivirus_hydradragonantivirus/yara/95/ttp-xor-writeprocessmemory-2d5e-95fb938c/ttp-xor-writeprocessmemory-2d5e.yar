rule TTP_XOR_WriteProcessMemory_2d5e {
  strings:
    $key_2d5e = { 7a 2c [2] 48 0e [2] 4e 3b [2] 60 3b [2] 5f 27 }

  condition:
    any of them
}