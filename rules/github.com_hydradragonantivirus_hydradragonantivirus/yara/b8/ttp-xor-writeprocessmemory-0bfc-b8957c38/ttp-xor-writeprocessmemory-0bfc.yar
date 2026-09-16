rule TTP_XOR_WriteProcessMemory_0bfc {
  strings:
    $key_0bfc = { 5c 8e [2] 6e ac [2] 68 99 [2] 46 99 [2] 79 85 }

  condition:
    any of them
}