rule TTP_XOR_WriteProcessMemory_4b5e {
  strings:
    $key_4b5e = { 1c 2c [2] 2e 0e [2] 28 3b [2] 06 3b [2] 39 27 }

  condition:
    any of them
}