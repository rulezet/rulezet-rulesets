rule TTP_XOR_WriteProcessMemory_c0b9 {
  strings:
    $key_c0b9 = { 97 cb [2] a5 e9 [2] a3 dc [2] 8d dc [2] b2 c0 }

  condition:
    any of them
}