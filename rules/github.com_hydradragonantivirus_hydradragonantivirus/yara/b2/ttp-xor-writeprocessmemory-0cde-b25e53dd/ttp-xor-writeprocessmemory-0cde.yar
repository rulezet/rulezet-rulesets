rule TTP_XOR_WriteProcessMemory_0cde {
  strings:
    $key_0cde = { 5b ac [2] 69 8e [2] 6f bb [2] 41 bb [2] 7e a7 }

  condition:
    any of them
}