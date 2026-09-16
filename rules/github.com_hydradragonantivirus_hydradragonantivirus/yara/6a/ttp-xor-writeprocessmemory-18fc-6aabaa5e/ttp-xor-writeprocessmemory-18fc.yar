rule TTP_XOR_WriteProcessMemory_18fc {
  strings:
    $key_18fc = { 4f 8e [2] 7d ac [2] 7b 99 [2] 55 99 [2] 6a 85 }

  condition:
    any of them
}