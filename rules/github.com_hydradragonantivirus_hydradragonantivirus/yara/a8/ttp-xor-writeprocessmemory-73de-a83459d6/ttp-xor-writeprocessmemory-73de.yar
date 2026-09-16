rule TTP_XOR_WriteProcessMemory_73de {
  strings:
    $key_73de = { 24 ac [2] 16 8e [2] 10 bb [2] 3e bb [2] 01 a7 }

  condition:
    any of them
}