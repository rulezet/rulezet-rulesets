rule TTP_XOR_WriteProcessMemory_69fc {
  strings:
    $key_69fc = { 3e 8e [2] 0c ac [2] 0a 99 [2] 24 99 [2] 1b 85 }

  condition:
    any of them
}