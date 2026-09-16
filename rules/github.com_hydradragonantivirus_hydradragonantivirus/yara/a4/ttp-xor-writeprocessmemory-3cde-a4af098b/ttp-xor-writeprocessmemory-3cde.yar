rule TTP_XOR_WriteProcessMemory_3cde {
  strings:
    $key_3cde = { 6b ac [2] 59 8e [2] 5f bb [2] 71 bb [2] 4e a7 }

  condition:
    any of them
}