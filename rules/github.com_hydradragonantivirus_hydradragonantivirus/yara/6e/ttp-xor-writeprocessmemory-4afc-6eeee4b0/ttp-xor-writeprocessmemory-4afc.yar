rule TTP_XOR_WriteProcessMemory_4afc {
  strings:
    $key_4afc = { 1d 8e [2] 2f ac [2] 29 99 [2] 07 99 [2] 38 85 }

  condition:
    any of them
}