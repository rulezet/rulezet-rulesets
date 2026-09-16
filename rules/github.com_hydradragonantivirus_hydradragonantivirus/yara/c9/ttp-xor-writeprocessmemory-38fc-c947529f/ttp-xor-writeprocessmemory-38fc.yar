rule TTP_XOR_WriteProcessMemory_38fc {
  strings:
    $key_38fc = { 6f 8e [2] 5d ac [2] 5b 99 [2] 75 99 [2] 4a 85 }

  condition:
    any of them
}