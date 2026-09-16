rule TTP_XOR_WriteProcessMemory_4b2e {
  strings:
    $key_4b2e = { 1c 5c [2] 2e 7e [2] 28 4b [2] 06 4b [2] 39 57 }

  condition:
    any of them
}