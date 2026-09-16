rule TTP_XOR_WriteProcessMemory_591e {
  strings:
    $key_591e = { 0e 6c [2] 3c 4e [2] 3a 7b [2] 14 7b [2] 2b 67 }

  condition:
    any of them
}