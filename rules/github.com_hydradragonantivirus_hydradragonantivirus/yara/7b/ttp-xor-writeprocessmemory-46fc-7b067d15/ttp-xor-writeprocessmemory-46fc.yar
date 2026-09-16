rule TTP_XOR_WriteProcessMemory_46fc {
  strings:
    $key_46fc = { 11 8e [2] 23 ac [2] 25 99 [2] 0b 99 [2] 34 85 }

  condition:
    any of them
}