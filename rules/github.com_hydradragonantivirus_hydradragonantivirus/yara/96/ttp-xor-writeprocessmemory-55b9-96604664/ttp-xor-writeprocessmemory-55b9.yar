rule TTP_XOR_WriteProcessMemory_55b9 {
  strings:
    $key_55b9 = { 02 cb [2] 30 e9 [2] 36 dc [2] 18 dc [2] 27 c0 }

  condition:
    any of them
}