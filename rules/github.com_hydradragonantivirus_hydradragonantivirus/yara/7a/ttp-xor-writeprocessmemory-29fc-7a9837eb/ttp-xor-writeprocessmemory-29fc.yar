rule TTP_XOR_WriteProcessMemory_29fc {
  strings:
    $key_29fc = { 7e 8e [2] 4c ac [2] 4a 99 [2] 64 99 [2] 5b 85 }

  condition:
    any of them
}