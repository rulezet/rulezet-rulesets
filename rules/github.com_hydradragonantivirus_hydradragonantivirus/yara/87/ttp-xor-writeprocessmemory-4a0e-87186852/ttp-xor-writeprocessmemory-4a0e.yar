rule TTP_XOR_WriteProcessMemory_4a0e {
  strings:
    $key_4a0e = { 1d 7c [2] 2f 5e [2] 29 6b [2] 07 6b [2] 38 77 }

  condition:
    any of them
}