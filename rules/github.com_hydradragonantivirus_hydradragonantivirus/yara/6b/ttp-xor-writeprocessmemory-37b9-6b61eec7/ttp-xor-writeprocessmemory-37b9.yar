rule TTP_XOR_WriteProcessMemory_37b9 {
  strings:
    $key_37b9 = { 60 cb [2] 52 e9 [2] 54 dc [2] 7a dc [2] 45 c0 }

  condition:
    any of them
}