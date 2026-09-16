rule TTP_XOR_WriteProcessMemory_4e2e {
  strings:
    $key_4e2e = { 19 5c [2] 2b 7e [2] 2d 4b [2] 03 4b [2] 3c 57 }

  condition:
    any of them
}