rule TTP_XOR_WriteProcessMemory_4190 {
  strings:
    $key_4190 = { 16 e2 [2] 24 c0 [2] 22 f5 [2] 0c f5 [2] 33 e9 }

  condition:
    any of them
}