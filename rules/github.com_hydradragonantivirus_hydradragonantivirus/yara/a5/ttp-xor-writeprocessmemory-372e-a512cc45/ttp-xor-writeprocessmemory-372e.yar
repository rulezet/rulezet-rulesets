rule TTP_XOR_WriteProcessMemory_372e {
  strings:
    $key_372e = { 60 5c [2] 52 7e [2] 54 4b [2] 7a 4b [2] 45 57 }

  condition:
    any of them
}