rule TTP_XOR_WriteProcessMemory_afde {
  strings:
    $key_afde = { f8 ac [2] ca 8e [2] cc bb [2] e2 bb [2] dd a7 }

  condition:
    any of them
}