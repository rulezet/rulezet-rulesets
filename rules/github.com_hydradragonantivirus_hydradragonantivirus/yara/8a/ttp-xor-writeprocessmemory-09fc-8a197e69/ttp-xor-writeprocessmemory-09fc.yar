rule TTP_XOR_WriteProcessMemory_09fc {
  strings:
    $key_09fc = { 5e 8e [2] 6c ac [2] 6a 99 [2] 44 99 [2] 7b 85 }

  condition:
    any of them
}