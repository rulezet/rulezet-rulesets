rule TTP_XOR_WriteProcessMemory_53a7 {
  strings:
    $key_53a7 = { 04 d5 [2] 36 f7 [2] 30 c2 [2] 1e c2 [2] 21 de }

  condition:
    any of them
}