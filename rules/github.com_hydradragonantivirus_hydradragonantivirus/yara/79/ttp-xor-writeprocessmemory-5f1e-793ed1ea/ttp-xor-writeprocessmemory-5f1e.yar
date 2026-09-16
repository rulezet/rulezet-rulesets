rule TTP_XOR_WriteProcessMemory_5f1e {
  strings:
    $key_5f1e = { 08 6c [2] 3a 4e [2] 3c 7b [2] 12 7b [2] 2d 67 }

  condition:
    any of them
}