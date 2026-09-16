rule TTP_XOR_WriteProcessMemory_2d2e {
  strings:
    $key_2d2e = { 7a 5c [2] 48 7e [2] 4e 4b [2] 60 4b [2] 5f 57 }

  condition:
    any of them
}