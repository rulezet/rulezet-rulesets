rule TTP_XOR_WriteProcessMemory_590e {
  strings:
    $key_590e = { 0e 7c [2] 3c 5e [2] 3a 6b [2] 14 6b [2] 2b 77 }

  condition:
    any of them
}