rule TTP_XOR_WriteProcessMemory_4a3e {
  strings:
    $key_4a3e = { 1d 4c [2] 2f 6e [2] 29 5b [2] 07 5b [2] 38 47 }

  condition:
    any of them
}