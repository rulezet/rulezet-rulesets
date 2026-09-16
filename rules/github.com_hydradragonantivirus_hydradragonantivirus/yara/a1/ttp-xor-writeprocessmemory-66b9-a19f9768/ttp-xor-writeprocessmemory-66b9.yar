rule TTP_XOR_WriteProcessMemory_66b9 {
  strings:
    $key_66b9 = { 31 cb [2] 03 e9 [2] 05 dc [2] 2b dc [2] 14 c0 }

  condition:
    any of them
}