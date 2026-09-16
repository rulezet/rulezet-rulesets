rule TTP_XOR_WriteProcessMemory_d8de {
  strings:
    $key_d8de = { 8f ac [2] bd 8e [2] bb bb [2] 95 bb [2] aa a7 }

  condition:
    any of them
}