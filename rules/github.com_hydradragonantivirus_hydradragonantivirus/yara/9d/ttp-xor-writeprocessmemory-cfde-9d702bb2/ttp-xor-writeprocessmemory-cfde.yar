rule TTP_XOR_WriteProcessMemory_cfde {
  strings:
    $key_cfde = { 98 ac [2] aa 8e [2] ac bb [2] 82 bb [2] bd a7 }

  condition:
    any of them
}