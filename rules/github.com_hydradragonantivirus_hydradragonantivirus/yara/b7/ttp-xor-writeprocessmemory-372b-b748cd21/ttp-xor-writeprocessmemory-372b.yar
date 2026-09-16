rule TTP_XOR_WriteProcessMemory_372b {
  strings:
    $key_372b = { 60 59 [2] 52 7b [2] 54 4e [2] 7a 4e [2] 45 52 }

  condition:
    any of them
}