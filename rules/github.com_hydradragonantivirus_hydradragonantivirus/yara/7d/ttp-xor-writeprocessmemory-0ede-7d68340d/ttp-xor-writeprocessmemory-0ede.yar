rule TTP_XOR_WriteProcessMemory_0ede {
  strings:
    $key_0ede = { 59 ac [2] 6b 8e [2] 6d bb [2] 43 bb [2] 7c a7 }

  condition:
    any of them
}