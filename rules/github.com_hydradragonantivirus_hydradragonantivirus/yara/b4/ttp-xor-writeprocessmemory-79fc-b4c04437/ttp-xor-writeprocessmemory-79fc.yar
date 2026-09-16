rule TTP_XOR_WriteProcessMemory_79fc {
  strings:
    $key_79fc = { 2e 8e [2] 1c ac [2] 1a 99 [2] 34 99 [2] 0b 85 }

  condition:
    any of them
}