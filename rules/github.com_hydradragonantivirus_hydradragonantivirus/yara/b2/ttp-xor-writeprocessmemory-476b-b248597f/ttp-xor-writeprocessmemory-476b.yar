rule TTP_XOR_WriteProcessMemory_476b {
  strings:
    $key_476b = { 10 19 [2] 22 3b [2] 24 0e [2] 0a 0e [2] 35 12 }

  condition:
    any of them
}