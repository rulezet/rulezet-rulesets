rule TTP_XOR_WriteProcessMemory_7d00 {
  strings:
    $key_7d00 = { 2a 72 [2] 18 50 [2] 1e 65 [2] 30 65 [2] 0f 79 }

  condition:
    any of them
}