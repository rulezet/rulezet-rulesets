rule TTP_XOR_WriteProcessMemory_cbde {
  strings:
    $key_cbde = { 9c ac [2] ae 8e [2] a8 bb [2] 86 bb [2] b9 a7 }

  condition:
    any of them
}