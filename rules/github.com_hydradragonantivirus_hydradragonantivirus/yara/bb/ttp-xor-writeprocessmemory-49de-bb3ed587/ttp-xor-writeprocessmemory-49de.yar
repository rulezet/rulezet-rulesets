rule TTP_XOR_WriteProcessMemory_49de {
  strings:
    $key_49de = { 1e ac [2] 2c 8e [2] 2a bb [2] 04 bb [2] 3b a7 }

  condition:
    any of them
}