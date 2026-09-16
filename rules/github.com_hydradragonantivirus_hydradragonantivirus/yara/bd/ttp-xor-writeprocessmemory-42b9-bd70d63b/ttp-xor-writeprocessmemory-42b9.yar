rule TTP_XOR_WriteProcessMemory_42b9 {
  strings:
    $key_42b9 = { 15 cb [2] 27 e9 [2] 21 dc [2] 0f dc [2] 30 c0 }

  condition:
    any of them
}