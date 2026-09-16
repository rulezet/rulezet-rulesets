rule TTP_XOR_WriteProcessMemory_49f7 {
  strings:
    $key_49f7 = { 1e 85 [2] 2c a7 [2] 2a 92 [2] 04 92 [2] 3b 8e }

  condition:
    any of them
}