rule TTP_XOR_WriteProcessMemory_1320 {
  strings:
    $key_1320 = { 44 52 [2] 76 70 [2] 70 45 [2] 5e 45 [2] 61 59 }

  condition:
    any of them
}