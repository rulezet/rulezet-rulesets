rule TTP_XOR_WriteProcessMemory_0b7e {
  strings:
    $key_0b7e = { 5c 0c [2] 6e 2e [2] 68 1b [2] 46 1b [2] 79 07 }

  condition:
    any of them
}