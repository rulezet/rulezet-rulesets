rule TTP_XOR_WriteProcessMemory_e700 {
  strings:
    $key_e700 = { b0 72 [2] 82 50 [2] 84 65 [2] aa 65 [2] 95 79 }

  condition:
    any of them
}