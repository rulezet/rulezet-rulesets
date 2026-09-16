rule TTP_XOR_WriteProcessMemory_315e {
  strings:
    $key_315e = { 66 2c [2] 54 0e [2] 52 3b [2] 7c 3b [2] 43 27 }

  condition:
    any of them
}