rule TTP_XOR_WriteProcessMemory_3ede {
  strings:
    $key_3ede = { 69 ac [2] 5b 8e [2] 5d bb [2] 73 bb [2] 4c a7 }

  condition:
    any of them
}