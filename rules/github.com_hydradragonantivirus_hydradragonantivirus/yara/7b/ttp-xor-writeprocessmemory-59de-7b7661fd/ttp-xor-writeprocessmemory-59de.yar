rule TTP_XOR_WriteProcessMemory_59de {
  strings:
    $key_59de = { 0e ac [2] 3c 8e [2] 3a bb [2] 14 bb [2] 2b a7 }

  condition:
    any of them
}