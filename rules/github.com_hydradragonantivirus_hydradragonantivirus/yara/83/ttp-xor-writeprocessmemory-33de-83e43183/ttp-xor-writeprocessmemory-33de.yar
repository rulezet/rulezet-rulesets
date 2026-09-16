rule TTP_XOR_WriteProcessMemory_33de {
  strings:
    $key_33de = { 64 ac [2] 56 8e [2] 50 bb [2] 7e bb [2] 41 a7 }

  condition:
    any of them
}