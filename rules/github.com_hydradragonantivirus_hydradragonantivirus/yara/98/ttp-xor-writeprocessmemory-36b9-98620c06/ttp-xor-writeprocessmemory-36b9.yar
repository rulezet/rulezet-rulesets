rule TTP_XOR_WriteProcessMemory_36b9 {
  strings:
    $key_36b9 = { 61 cb [2] 53 e9 [2] 55 dc [2] 7b dc [2] 44 c0 }

  condition:
    any of them
}