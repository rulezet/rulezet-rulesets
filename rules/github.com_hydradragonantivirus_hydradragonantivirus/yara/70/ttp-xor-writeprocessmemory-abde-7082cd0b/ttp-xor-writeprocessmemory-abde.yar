rule TTP_XOR_WriteProcessMemory_abde {
  strings:
    $key_abde = { fc ac [2] ce 8e [2] c8 bb [2] e6 bb [2] d9 a7 }

  condition:
    any of them
}