rule TTP_XOR_WriteProcessMemory_4bf0 {
  strings:
    $key_4bf0 = { 1c 82 [2] 2e a0 [2] 28 95 [2] 06 95 [2] 39 89 }

  condition:
    any of them
}