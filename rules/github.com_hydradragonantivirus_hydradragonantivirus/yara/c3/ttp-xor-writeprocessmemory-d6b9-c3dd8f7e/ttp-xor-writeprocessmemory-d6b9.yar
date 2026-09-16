rule TTP_XOR_WriteProcessMemory_d6b9 {
  strings:
    $key_d6b9 = { 81 cb [2] b3 e9 [2] b5 dc [2] 9b dc [2] a4 c0 }

  condition:
    any of them
}