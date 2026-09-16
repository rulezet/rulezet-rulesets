rule TTP_XOR_WriteProcessMemory_51a5 {
  strings:
    $key_51a5 = { 06 d7 [2] 34 f5 [2] 32 c0 [2] 1c c0 [2] 23 dc }

  condition:
    any of them
}