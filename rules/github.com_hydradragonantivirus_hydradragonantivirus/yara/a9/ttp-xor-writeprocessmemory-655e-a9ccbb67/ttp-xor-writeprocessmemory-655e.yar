rule TTP_XOR_WriteProcessMemory_655e {
  strings:
    $key_655e = { 32 2c [2] 00 0e [2] 06 3b [2] 28 3b [2] 17 27 }

  condition:
    any of them
}