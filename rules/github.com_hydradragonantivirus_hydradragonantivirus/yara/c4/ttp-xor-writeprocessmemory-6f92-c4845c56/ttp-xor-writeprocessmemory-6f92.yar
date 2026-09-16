rule TTP_XOR_WriteProcessMemory_6f92 {
  strings:
    $key_6f92 = { 38 e0 [2] 0a c2 [2] 0c f7 [2] 22 f7 [2] 1d eb }

  condition:
    any of them
}