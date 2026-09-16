rule TTP_XOR_WriteProcessMemory_345e {
  strings:
    $key_345e = { 63 2c [2] 51 0e [2] 57 3b [2] 79 3b [2] 46 27 }

  condition:
    any of them
}