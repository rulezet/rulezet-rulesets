rule TTP_XOR_WriteProcessMemory_e290 {
  strings:
    $key_e290 = { b5 e2 [2] 87 c0 [2] 81 f5 [2] af f5 [2] 90 e9 }

  condition:
    any of them
}