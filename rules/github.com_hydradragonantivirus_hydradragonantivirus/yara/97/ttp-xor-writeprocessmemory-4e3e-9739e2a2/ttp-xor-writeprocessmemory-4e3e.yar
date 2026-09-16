rule TTP_XOR_WriteProcessMemory_4e3e {
  strings:
    $key_4e3e = { 19 4c [2] 2b 6e [2] 2d 5b [2] 03 5b [2] 3c 47 }

  condition:
    any of them
}