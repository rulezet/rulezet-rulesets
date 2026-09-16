rule TTP_XOR_WriteProcessMemory_273e {
  strings:
    $key_273e = { 70 4c [2] 42 6e [2] 44 5b [2] 6a 5b [2] 55 47 }

  condition:
    any of them
}