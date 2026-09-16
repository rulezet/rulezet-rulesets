rule TTP_XOR_WriteProcessMemory_5f3e {
  strings:
    $key_5f3e = { 08 4c [2] 3a 6e [2] 3c 5b [2] 12 5b [2] 2d 47 }

  condition:
    any of them
}