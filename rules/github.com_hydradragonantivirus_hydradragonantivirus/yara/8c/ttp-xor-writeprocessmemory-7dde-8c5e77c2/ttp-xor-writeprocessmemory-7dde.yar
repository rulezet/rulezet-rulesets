rule TTP_XOR_WriteProcessMemory_7dde {
  strings:
    $key_7dde = { 2a ac [2] 18 8e [2] 1e bb [2] 30 bb [2] 0f a7 }

  condition:
    any of them
}