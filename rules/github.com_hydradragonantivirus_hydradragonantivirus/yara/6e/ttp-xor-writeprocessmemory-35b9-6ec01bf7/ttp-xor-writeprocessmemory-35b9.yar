rule TTP_XOR_WriteProcessMemory_35b9 {
  strings:
    $key_35b9 = { 62 cb [2] 50 e9 [2] 56 dc [2] 78 dc [2] 47 c0 }

  condition:
    any of them
}