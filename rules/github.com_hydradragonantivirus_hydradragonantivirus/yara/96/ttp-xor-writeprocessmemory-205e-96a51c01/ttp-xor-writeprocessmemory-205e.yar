rule TTP_XOR_WriteProcessMemory_205e {
  strings:
    $key_205e = { 77 2c [2] 45 0e [2] 43 3b [2] 6d 3b [2] 52 27 }

  condition:
    any of them
}