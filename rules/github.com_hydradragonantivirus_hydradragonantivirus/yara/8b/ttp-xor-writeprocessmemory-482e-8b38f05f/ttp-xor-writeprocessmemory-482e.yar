rule TTP_XOR_WriteProcessMemory_482e {
  strings:
    $key_482e = { 1f 5c [2] 2d 7e [2] 2b 4b [2] 05 4b [2] 3a 57 }

  condition:
    any of them
}