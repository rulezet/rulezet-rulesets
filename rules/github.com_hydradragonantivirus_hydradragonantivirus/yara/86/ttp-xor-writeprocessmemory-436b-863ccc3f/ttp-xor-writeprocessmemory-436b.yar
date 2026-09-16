rule TTP_XOR_WriteProcessMemory_436b {
  strings:
    $key_436b = { 14 19 [2] 26 3b [2] 20 0e [2] 0e 0e [2] 31 12 }

  condition:
    any of them
}