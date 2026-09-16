rule TTP_XOR_WriteProcessMemory_77a5 {
  strings:
    $key_77a5 = { 20 d7 [2] 12 f5 [2] 14 c0 [2] 3a c0 [2] 05 dc }

  condition:
    any of them
}