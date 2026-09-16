rule TTP_XOR_WriteProcessMemory_d0b9 {
  strings:
    $key_d0b9 = { 87 cb [2] b5 e9 [2] b3 dc [2] 9d dc [2] a2 c0 }

  condition:
    any of them
}