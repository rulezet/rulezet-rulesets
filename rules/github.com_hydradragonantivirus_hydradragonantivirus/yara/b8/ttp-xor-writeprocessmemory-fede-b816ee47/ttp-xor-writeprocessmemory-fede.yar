rule TTP_XOR_WriteProcessMemory_fede {
  strings:
    $key_fede = { a9 ac [2] 9b 8e [2] 9d bb [2] b3 bb [2] 8c a7 }

  condition:
    any of them
}