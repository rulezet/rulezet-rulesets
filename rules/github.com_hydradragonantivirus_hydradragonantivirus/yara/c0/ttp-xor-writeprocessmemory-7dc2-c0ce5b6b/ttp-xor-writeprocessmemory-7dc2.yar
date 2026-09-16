rule TTP_XOR_WriteProcessMemory_7dc2 {
  strings:
    $key_7dc2 = { 2a b0 [2] 18 92 [2] 1e a7 [2] 30 a7 [2] 0f bb }

  condition:
    any of them
}