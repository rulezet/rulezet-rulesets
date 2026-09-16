rule TTP_XOR_WriteProcessMemory_fa5e {
  strings:
    $key_fa5e = { ad 2c [2] 9f 0e [2] 99 3b [2] b7 3b [2] 88 27 }

  condition:
    any of them
}