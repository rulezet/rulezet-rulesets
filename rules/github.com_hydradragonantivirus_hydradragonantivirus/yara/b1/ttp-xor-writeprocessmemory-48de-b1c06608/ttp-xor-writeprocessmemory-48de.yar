rule TTP_XOR_WriteProcessMemory_48de {
  strings:
    $key_48de = { 1f ac [2] 2d 8e [2] 2b bb [2] 05 bb [2] 3a a7 }

  condition:
    any of them
}