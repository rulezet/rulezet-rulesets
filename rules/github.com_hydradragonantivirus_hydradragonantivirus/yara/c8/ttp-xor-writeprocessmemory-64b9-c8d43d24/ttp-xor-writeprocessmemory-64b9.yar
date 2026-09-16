rule TTP_XOR_WriteProcessMemory_64b9 {
  strings:
    $key_64b9 = { 33 cb [2] 01 e9 [2] 07 dc [2] 29 dc [2] 16 c0 }

  condition:
    any of them
}