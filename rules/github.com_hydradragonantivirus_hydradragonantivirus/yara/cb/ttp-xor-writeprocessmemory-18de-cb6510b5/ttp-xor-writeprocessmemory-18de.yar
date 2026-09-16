rule TTP_XOR_WriteProcessMemory_18de {
  strings:
    $key_18de = { 4f ac [2] 7d 8e [2] 7b bb [2] 55 bb [2] 6a a7 }

  condition:
    any of them
}