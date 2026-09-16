rule TTP_XOR_WriteProcessMemory_ff5e {
  strings:
    $key_ff5e = { a8 2c [2] 9a 0e [2] 9c 3b [2] b2 3b [2] 8d 27 }

  condition:
    any of them
}