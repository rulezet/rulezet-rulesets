rule TTP_XOR_WriteProcessMemory_6b2e {
  strings:
    $key_6b2e = { 3c 5c [2] 0e 7e [2] 08 4b [2] 26 4b [2] 19 57 }

  condition:
    any of them
}