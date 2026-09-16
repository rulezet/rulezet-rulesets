rule TTP_XOR_WriteProcessMemory_12a5 {
  strings:
    $key_12a5 = { 45 d7 [2] 77 f5 [2] 71 c0 [2] 5f c0 [2] 60 dc }

  condition:
    any of them
}