rule TTP_XOR_WriteProcessMemory_5322 {
  strings:
    $key_5322 = { 04 50 [2] 36 72 [2] 30 47 [2] 1e 47 [2] 21 5b }

  condition:
    any of them
}