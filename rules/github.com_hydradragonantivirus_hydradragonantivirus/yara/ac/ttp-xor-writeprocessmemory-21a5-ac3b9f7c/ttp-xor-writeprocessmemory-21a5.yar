rule TTP_XOR_WriteProcessMemory_21a5 {
  strings:
    $key_21a5 = { 76 d7 [2] 44 f5 [2] 42 c0 [2] 6c c0 [2] 53 dc }

  condition:
    any of them
}