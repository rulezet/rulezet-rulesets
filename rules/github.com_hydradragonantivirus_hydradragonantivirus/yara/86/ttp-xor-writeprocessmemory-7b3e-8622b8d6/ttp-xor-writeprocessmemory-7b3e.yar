rule TTP_XOR_WriteProcessMemory_7b3e {
  strings:
    $key_7b3e = { 2c 4c [2] 1e 6e [2] 18 5b [2] 36 5b [2] 09 47 }

  condition:
    any of them
}