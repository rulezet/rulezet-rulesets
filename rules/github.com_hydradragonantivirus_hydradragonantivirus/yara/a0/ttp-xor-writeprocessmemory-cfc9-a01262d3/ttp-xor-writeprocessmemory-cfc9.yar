rule TTP_XOR_WriteProcessMemory_cfc9 {
  strings:
    $key_cfc9 = { 98 bb [2] aa 99 [2] ac ac [2] 82 ac [2] bd b0 }

  condition:
    any of them
}