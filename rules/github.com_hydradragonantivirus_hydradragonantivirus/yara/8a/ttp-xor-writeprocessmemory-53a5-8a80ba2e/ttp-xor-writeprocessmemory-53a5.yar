rule TTP_XOR_WriteProcessMemory_53a5 {
  strings:
    $key_53a5 = { 04 d7 [2] 36 f5 [2] 30 c0 [2] 1e c0 [2] 21 dc }

  condition:
    any of them
}