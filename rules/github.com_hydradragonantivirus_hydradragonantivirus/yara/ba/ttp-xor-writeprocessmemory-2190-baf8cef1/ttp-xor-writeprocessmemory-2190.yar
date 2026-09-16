rule TTP_XOR_WriteProcessMemory_2190 {
  strings:
    $key_2190 = { 76 e2 [2] 44 c0 [2] 42 f5 [2] 6c f5 [2] 53 e9 }

  condition:
    any of them
}