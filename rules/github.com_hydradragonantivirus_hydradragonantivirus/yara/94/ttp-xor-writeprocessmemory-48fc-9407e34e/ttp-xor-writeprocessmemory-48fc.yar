rule TTP_XOR_WriteProcessMemory_48fc {
  strings:
    $key_48fc = { 1f 8e [2] 2d ac [2] 2b 99 [2] 05 99 [2] 3a 85 }

  condition:
    any of them
}