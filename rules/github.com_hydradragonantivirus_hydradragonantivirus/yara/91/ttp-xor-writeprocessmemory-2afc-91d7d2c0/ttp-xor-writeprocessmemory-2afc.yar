rule TTP_XOR_WriteProcessMemory_2afc {
  strings:
    $key_2afc = { 7d 8e [2] 4f ac [2] 49 99 [2] 67 99 [2] 58 85 }

  condition:
    any of them
}