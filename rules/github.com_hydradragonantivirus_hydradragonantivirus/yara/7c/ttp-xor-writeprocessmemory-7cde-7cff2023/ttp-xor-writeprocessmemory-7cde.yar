rule TTP_XOR_WriteProcessMemory_7cde {
  strings:
    $key_7cde = { 2b ac [2] 19 8e [2] 1f bb [2] 31 bb [2] 0e a7 }

  condition:
    any of them
}