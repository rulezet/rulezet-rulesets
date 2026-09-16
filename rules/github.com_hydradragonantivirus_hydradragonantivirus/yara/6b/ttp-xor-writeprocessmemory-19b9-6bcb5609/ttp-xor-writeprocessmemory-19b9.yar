rule TTP_XOR_WriteProcessMemory_19b9 {
  strings:
    $key_19b9 = { 4e cb [2] 7c e9 [2] 7a dc [2] 54 dc [2] 6b c0 }

  condition:
    any of them
}