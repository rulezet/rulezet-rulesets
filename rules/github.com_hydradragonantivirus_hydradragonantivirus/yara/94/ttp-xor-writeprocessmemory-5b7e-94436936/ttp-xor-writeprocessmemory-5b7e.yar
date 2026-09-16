rule TTP_XOR_WriteProcessMemory_5b7e {
  strings:
    $key_5b7e = { 0c 0c [2] 3e 2e [2] 38 1b [2] 16 1b [2] 29 07 }

  condition:
    any of them
}