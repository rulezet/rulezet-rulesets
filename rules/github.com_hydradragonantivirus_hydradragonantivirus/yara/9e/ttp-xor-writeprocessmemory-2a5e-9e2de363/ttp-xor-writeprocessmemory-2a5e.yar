rule TTP_XOR_WriteProcessMemory_2a5e {
  strings:
    $key_2a5e = { 7d 2c [2] 4f 0e [2] 49 3b [2] 67 3b [2] 58 27 }

  condition:
    any of them
}