rule TTP_XOR_WriteProcessMemory_4c0e {
  strings:
    $key_4c0e = { 1b 7c [2] 29 5e [2] 2f 6b [2] 01 6b [2] 3e 77 }

  condition:
    any of them
}