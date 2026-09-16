rule TTP_XOR_WriteProcessMemory_0a5e {
  strings:
    $key_0a5e = { 5d 2c [2] 6f 0e [2] 69 3b [2] 47 3b [2] 78 27 }

  condition:
    any of them
}