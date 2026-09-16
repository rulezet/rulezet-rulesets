rule TTP_XOR_WriteProcessMemory_24b9 {
  strings:
    $key_24b9 = { 73 cb [2] 41 e9 [2] 47 dc [2] 69 dc [2] 56 c0 }

  condition:
    any of them
}