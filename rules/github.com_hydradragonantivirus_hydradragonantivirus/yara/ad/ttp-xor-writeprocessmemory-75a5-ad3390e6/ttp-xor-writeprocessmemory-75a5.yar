rule TTP_XOR_WriteProcessMemory_75a5 {
  strings:
    $key_75a5 = { 22 d7 [2] 10 f5 [2] 16 c0 [2] 38 c0 [2] 07 dc }

  condition:
    any of them
}