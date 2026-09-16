rule TTP_XOR_WriteProcessMemory_7b5e {
  strings:
    $key_7b5e = { 2c 2c [2] 1e 0e [2] 18 3b [2] 36 3b [2] 09 27 }

  condition:
    any of them
}