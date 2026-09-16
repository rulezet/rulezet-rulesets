rule TTP_XOR_WriteProcessMemory_757e {
  strings:
    $key_757e = { 22 0c [2] 10 2e [2] 16 1b [2] 38 1b [2] 07 07 }

  condition:
    any of them
}