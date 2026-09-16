rule TTP_XOR_WriteProcessMemory_5ba5 {
  strings:
    $key_5ba5 = { 0c d7 [2] 3e f5 [2] 38 c0 [2] 16 c0 [2] 29 dc }

  condition:
    any of them
}