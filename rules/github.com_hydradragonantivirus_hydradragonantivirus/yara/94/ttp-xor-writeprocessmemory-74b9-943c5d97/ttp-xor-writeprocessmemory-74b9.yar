rule TTP_XOR_WriteProcessMemory_74b9 {
  strings:
    $key_74b9 = { 23 cb [2] 11 e9 [2] 17 dc [2] 39 dc [2] 06 c0 }

  condition:
    any of them
}