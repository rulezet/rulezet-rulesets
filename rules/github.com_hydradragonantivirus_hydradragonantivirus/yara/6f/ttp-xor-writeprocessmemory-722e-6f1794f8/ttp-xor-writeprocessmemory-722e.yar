rule TTP_XOR_WriteProcessMemory_722e {
  strings:
    $key_722e = { 25 5c [2] 17 7e [2] 11 4b [2] 3f 4b [2] 00 57 }

  condition:
    any of them
}