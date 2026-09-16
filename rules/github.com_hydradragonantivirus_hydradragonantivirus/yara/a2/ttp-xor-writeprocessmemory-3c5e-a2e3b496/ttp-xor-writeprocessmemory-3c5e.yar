rule TTP_XOR_WriteProcessMemory_3c5e {
  strings:
    $key_3c5e = { 6b 2c [2] 59 0e [2] 5f 3b [2] 71 3b [2] 4e 27 }

  condition:
    any of them
}