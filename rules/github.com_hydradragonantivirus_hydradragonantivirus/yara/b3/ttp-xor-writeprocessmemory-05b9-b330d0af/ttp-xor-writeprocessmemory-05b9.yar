rule TTP_XOR_WriteProcessMemory_05b9 {
  strings:
    $key_05b9 = { 52 cb [2] 60 e9 [2] 66 dc [2] 48 dc [2] 77 c0 }

  condition:
    any of them
}