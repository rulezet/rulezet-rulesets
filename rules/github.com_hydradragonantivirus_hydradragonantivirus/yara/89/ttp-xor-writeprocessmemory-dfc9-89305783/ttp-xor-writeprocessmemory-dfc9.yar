rule TTP_XOR_WriteProcessMemory_dfc9 {
  strings:
    $key_dfc9 = { 88 bb [2] ba 99 [2] bc ac [2] 92 ac [2] ad b0 }

  condition:
    any of them
}