rule TTP_XOR_WriteProcessMemory_4e4e {
  strings:
    $key_4e4e = { 19 3c [2] 2b 1e [2] 2d 2b [2] 03 2b [2] 3c 37 }

  condition:
    any of them
}