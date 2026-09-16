rule TTP_XOR_WriteProcessMemory_8dde {
  strings:
    $key_8dde = { da ac [2] e8 8e [2] ee bb [2] c0 bb [2] ff a7 }

  condition:
    any of them
}