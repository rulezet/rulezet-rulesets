rule TTP_XOR_WriteProcessMemory_0dde {
  strings:
    $key_0dde = { 5a ac [2] 68 8e [2] 6e bb [2] 40 bb [2] 7f a7 }

  condition:
    any of them
}