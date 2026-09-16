rule TTP_XOR_WriteProcessMemory_38de {
  strings:
    $key_38de = { 6f ac [2] 5d 8e [2] 5b bb [2] 75 bb [2] 4a a7 }

  condition:
    any of them
}