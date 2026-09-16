rule TTP_XOR_WriteProcessMemory_733e {
  strings:
    $key_733e = { 24 4c [2] 16 6e [2] 10 5b [2] 3e 5b [2] 01 47 }

  condition:
    any of them
}