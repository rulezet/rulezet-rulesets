rule TTP_XOR_WriteProcessMemory_57fc {
  strings:
    $key_57fc = { 00 8e [2] 32 ac [2] 34 99 [2] 1a 99 [2] 25 85 }

  condition:
    any of them
}