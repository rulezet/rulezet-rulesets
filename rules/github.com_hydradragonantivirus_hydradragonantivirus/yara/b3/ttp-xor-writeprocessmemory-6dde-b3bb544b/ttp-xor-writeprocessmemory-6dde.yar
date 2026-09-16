rule TTP_XOR_WriteProcessMemory_6dde {
  strings:
    $key_6dde = { 3a ac [2] 08 8e [2] 0e bb [2] 20 bb [2] 1f a7 }

  condition:
    any of them
}