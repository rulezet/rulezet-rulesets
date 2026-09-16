rule TTP_XOR_WriteProcessMemory_1bfc {
  strings:
    $key_1bfc = { 4c 8e [2] 7e ac [2] 78 99 [2] 56 99 [2] 69 85 }

  condition:
    any of them
}