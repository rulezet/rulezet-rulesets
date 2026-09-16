rule TTP_XOR_WriteProcessMemory_2d4e {
  strings:
    $key_2d4e = { 7a 3c [2] 48 1e [2] 4e 2b [2] 60 2b [2] 5f 37 }

  condition:
    any of them
}