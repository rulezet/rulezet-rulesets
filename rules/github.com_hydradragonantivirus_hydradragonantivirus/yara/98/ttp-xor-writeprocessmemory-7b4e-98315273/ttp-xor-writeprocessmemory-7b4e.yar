rule TTP_XOR_WriteProcessMemory_7b4e {
  strings:
    $key_7b4e = { 2c 3c [2] 1e 1e [2] 18 2b [2] 36 2b [2] 09 37 }

  condition:
    any of them
}