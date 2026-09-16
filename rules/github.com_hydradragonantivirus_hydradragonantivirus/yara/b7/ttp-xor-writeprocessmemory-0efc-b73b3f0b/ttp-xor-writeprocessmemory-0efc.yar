rule TTP_XOR_WriteProcessMemory_0efc {
  strings:
    $key_0efc = { 59 8e [2] 6b ac [2] 6d 99 [2] 43 99 [2] 7c 85 }

  condition:
    any of them
}