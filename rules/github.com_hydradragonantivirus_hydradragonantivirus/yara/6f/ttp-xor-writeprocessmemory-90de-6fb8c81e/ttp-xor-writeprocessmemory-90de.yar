rule TTP_XOR_WriteProcessMemory_90de {
  strings:
    $key_90de = { c7 ac [2] f5 8e [2] f3 bb [2] dd bb [2] e2 a7 }

  condition:
    any of them
}