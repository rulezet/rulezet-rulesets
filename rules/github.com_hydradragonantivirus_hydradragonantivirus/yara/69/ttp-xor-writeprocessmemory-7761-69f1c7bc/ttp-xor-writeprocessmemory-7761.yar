rule TTP_XOR_WriteProcessMemory_7761 {
  strings:
    $key_7761 = { 20 13 [2] 12 31 [2] 14 04 [2] 3a 04 [2] 05 18 }

  condition:
    any of them
}