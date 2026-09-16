rule TTP_XOR_WriteProcessMemory_c7b9 {
  strings:
    $key_c7b9 = { 90 cb [2] a2 e9 [2] a4 dc [2] 8a dc [2] b5 c0 }

  condition:
    any of them
}