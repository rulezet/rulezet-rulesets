rule TTP_XOR_WriteProcessMemory_59b9 {
  strings:
    $key_59b9 = { 0e cb [2] 3c e9 [2] 3a dc [2] 14 dc [2] 2b c0 }

  condition:
    any of them
}