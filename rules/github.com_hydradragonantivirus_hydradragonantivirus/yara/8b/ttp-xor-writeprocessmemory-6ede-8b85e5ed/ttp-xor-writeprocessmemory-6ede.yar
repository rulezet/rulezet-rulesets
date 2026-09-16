rule TTP_XOR_WriteProcessMemory_6ede {
  strings:
    $key_6ede = { 39 ac [2] 0b 8e [2] 0d bb [2] 23 bb [2] 1c a7 }

  condition:
    any of them
}