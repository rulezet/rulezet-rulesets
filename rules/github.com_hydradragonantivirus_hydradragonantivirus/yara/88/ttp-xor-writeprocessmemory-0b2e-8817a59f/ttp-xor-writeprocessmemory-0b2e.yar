rule TTP_XOR_WriteProcessMemory_0b2e {
  strings:
    $key_0b2e = { 5c 5c [2] 6e 7e [2] 68 4b [2] 46 4b [2] 79 57 }

  condition:
    any of them
}