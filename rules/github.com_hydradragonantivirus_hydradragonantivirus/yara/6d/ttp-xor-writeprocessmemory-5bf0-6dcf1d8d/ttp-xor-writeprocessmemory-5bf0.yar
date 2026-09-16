rule TTP_XOR_WriteProcessMemory_5bf0 {
  strings:
    $key_5bf0 = { 0c 82 [2] 3e a0 [2] 38 95 [2] 16 95 [2] 29 89 }

  condition:
    any of them
}