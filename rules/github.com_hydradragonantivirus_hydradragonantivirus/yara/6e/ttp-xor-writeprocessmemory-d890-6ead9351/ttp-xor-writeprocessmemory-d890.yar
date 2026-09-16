rule TTP_XOR_WriteProcessMemory_d890 {
  strings:
    $key_d890 = { 8f e2 [2] bd c0 [2] bb f5 [2] 95 f5 [2] aa e9 }

  condition:
    any of them
}