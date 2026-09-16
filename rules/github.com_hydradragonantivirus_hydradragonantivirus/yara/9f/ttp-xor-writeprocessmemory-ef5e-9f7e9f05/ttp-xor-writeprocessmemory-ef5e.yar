rule TTP_XOR_WriteProcessMemory_ef5e {
  strings:
    $key_ef5e = { b8 2c [2] 8a 0e [2] 8c 3b [2] a2 3b [2] 9d 27 }

  condition:
    any of them
}