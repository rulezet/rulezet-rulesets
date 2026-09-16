rule TTP_XOR_WriteProcessMemory_1e5e {
  strings:
    $key_1e5e = { 49 2c [2] 7b 0e [2] 7d 3b [2] 53 3b [2] 6c 27 }

  condition:
    any of them
}