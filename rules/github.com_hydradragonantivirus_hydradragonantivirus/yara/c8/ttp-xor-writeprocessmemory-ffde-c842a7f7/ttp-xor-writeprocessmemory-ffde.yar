rule TTP_XOR_WriteProcessMemory_ffde {
  strings:
    $key_ffde = { a8 ac [2] 9a 8e [2] 9c bb [2] b2 bb [2] 8d a7 }

  condition:
    any of them
}