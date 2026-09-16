rule TTP_XOR_WriteProcessMemory_4e1e {
  strings:
    $key_4e1e = { 19 6c [2] 2b 4e [2] 2d 7b [2] 03 7b [2] 3c 67 }

  condition:
    any of them
}