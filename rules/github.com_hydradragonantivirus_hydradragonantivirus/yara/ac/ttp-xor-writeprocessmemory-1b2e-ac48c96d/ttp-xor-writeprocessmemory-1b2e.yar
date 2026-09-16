rule TTP_XOR_WriteProcessMemory_1b2e {
  strings:
    $key_1b2e = { 4c 5c [2] 7e 7e [2] 78 4b [2] 56 4b [2] 69 57 }

  condition:
    any of them
}