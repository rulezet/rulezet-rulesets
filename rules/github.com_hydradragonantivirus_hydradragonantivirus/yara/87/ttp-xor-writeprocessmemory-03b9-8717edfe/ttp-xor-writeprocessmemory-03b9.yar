rule TTP_XOR_WriteProcessMemory_03b9 {
  strings:
    $key_03b9 = { 54 cb [2] 66 e9 [2] 60 dc [2] 4e dc [2] 71 c0 }

  condition:
    any of them
}