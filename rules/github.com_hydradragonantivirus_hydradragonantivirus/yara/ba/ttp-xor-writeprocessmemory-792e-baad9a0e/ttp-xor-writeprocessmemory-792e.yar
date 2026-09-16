rule TTP_XOR_WriteProcessMemory_792e {
  strings:
    $key_792e = { 2e 5c [2] 1c 7e [2] 1a 4b [2] 34 4b [2] 0b 57 }

  condition:
    any of them
}