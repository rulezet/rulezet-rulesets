rule TTP_XOR_WriteProcessMemory_0d5e {
  strings:
    $key_0d5e = { 5a 2c [2] 68 0e [2] 6e 3b [2] 40 3b [2] 7f 27 }

  condition:
    any of them
}