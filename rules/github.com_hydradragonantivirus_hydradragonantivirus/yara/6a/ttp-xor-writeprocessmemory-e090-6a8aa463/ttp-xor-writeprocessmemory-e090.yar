rule TTP_XOR_WriteProcessMemory_e090 {
  strings:
    $key_e090 = { b7 e2 [2] 85 c0 [2] 83 f5 [2] ad f5 [2] 92 e9 }

  condition:
    any of them
}