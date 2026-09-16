rule TTP_XOR_WriteProcessMemory_7bf0 {
  strings:
    $key_7bf0 = { 2c 82 [2] 1e a0 [2] 18 95 [2] 36 95 [2] 09 89 }

  condition:
    any of them
}