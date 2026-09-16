rule TTP_XOR_WriteProcessMemory_5d0e {
  strings:
    $key_5d0e = { 0a 7c [2] 38 5e [2] 3e 6b [2] 10 6b [2] 2f 77 }

  condition:
    any of them
}