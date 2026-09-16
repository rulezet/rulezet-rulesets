rule TTP_XOR_WriteProcessMemory_503e {
  strings:
    $key_503e = { 07 4c [2] 35 6e [2] 33 5b [2] 1d 5b [2] 22 47 }

  condition:
    any of them
}