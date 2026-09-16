rule TTP_XOR_WriteProcessMemory_6ba5 {
  strings:
    $key_6ba5 = { 3c d7 [2] 0e f5 [2] 08 c0 [2] 26 c0 [2] 19 dc }

  condition:
    any of them
}