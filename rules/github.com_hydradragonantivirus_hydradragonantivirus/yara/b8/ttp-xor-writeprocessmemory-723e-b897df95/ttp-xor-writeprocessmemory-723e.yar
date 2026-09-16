rule TTP_XOR_WriteProcessMemory_723e {
  strings:
    $key_723e = { 25 4c [2] 17 6e [2] 11 5b [2] 3f 5b [2] 00 47 }

  condition:
    any of them
}