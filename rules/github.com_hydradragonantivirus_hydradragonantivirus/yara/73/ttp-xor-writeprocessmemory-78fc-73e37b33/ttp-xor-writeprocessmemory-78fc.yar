rule TTP_XOR_WriteProcessMemory_78fc {
  strings:
    $key_78fc = { 2f 8e [2] 1d ac [2] 1b 99 [2] 35 99 [2] 0a 85 }

  condition:
    any of them
}