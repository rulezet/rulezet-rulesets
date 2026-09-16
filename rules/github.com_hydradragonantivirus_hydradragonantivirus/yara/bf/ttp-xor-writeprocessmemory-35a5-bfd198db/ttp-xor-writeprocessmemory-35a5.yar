rule TTP_XOR_WriteProcessMemory_35a5 {
  strings:
    $key_35a5 = { 62 d7 [2] 50 f5 [2] 56 c0 [2] 78 c0 [2] 47 dc }

  condition:
    any of them
}