rule TTP_XOR_WriteProcessMemory_53fc {
  strings:
    $key_53fc = { 04 8e [2] 36 ac [2] 30 99 [2] 1e 99 [2] 21 85 }

  condition:
    any of them
}