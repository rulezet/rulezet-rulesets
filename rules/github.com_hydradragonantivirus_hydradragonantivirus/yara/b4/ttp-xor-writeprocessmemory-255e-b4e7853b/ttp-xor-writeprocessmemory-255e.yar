rule TTP_XOR_WriteProcessMemory_255e {
  strings:
    $key_255e = { 72 2c [2] 40 0e [2] 46 3b [2] 68 3b [2] 57 27 }

  condition:
    any of them
}