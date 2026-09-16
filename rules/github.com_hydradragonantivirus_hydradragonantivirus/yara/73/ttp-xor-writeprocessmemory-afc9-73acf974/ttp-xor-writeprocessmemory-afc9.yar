rule TTP_XOR_WriteProcessMemory_afc9 {
  strings:
    $key_afc9 = { f8 bb [2] ca 99 [2] cc ac [2] e2 ac [2] dd b0 }

  condition:
    any of them
}