rule TTP_XOR_WriteProcessMemory_25a5 {
  strings:
    $key_25a5 = { 72 d7 [2] 40 f5 [2] 46 c0 [2] 68 c0 [2] 57 dc }

  condition:
    any of them
}