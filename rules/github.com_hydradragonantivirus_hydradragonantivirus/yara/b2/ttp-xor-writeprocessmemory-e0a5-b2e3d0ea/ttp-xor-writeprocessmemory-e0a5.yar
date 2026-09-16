rule TTP_XOR_WriteProcessMemory_e0a5 {
  strings:
    $key_e0a5 = { b7 d7 [2] 85 f5 [2] 83 c0 [2] ad c0 [2] 92 dc }

  condition:
    any of them
}