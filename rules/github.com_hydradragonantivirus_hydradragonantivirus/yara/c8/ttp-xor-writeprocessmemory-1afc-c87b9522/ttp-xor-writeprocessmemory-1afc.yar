rule TTP_XOR_WriteProcessMemory_1afc {
  strings:
    $key_1afc = { 4d 8e [2] 7f ac [2] 79 99 [2] 57 99 [2] 68 85 }

  condition:
    any of them
}