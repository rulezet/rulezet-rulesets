rule TTP_XOR_WriteProcessMemory_e7b9 {
  strings:
    $key_e7b9 = { b0 cb [2] 82 e9 [2] 84 dc [2] aa dc [2] 95 c0 }

  condition:
    any of them
}