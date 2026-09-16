rule TTP_XOR_WriteProcessMemory_0ffc {
  strings:
    $key_0ffc = { 58 8e [2] 6a ac [2] 6c 99 [2] 42 99 [2] 7d 85 }

  condition:
    any of them
}