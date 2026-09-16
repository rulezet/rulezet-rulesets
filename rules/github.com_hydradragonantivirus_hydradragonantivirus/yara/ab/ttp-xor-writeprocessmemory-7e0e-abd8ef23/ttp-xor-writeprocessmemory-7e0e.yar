rule TTP_XOR_WriteProcessMemory_7e0e {
  strings:
    $key_7e0e = { 29 7c [2] 1b 5e [2] 1d 6b [2] 33 6b [2] 0c 77 }

  condition:
    any of them
}