rule TTP_XOR_WriteProcessMemory_c9fc {
  strings:
    $key_c9fc = { 9e 8e [2] ac ac [2] aa 99 [2] 84 99 [2] bb 85 }

  condition:
    any of them
}