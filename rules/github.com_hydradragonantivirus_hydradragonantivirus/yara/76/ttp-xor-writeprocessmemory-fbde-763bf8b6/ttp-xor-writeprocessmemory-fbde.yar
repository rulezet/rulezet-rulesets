rule TTP_XOR_WriteProcessMemory_fbde {
  strings:
    $key_fbde = { ac ac [2] 9e 8e [2] 98 bb [2] b6 bb [2] 89 a7 }

  condition:
    any of them
}