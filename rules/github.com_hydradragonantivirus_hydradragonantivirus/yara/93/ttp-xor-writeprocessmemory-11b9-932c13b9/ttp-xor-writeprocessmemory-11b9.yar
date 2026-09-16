rule TTP_XOR_WriteProcessMemory_11b9 {
  strings:
    $key_11b9 = { 46 cb [2] 74 e9 [2] 72 dc [2] 5c dc [2] 63 c0 }

  condition:
    any of them
}