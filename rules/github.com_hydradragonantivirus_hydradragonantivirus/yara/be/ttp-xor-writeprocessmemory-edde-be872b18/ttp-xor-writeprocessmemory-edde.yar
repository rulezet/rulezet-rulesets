rule TTP_XOR_WriteProcessMemory_edde {
  strings:
    $key_edde = { ba ac [2] 88 8e [2] 8e bb [2] a0 bb [2] 9f a7 }

  condition:
    any of them
}