rule TTP_XOR_WriteProcessMemory_47a5 {
  strings:
    $key_47a5 = { 10 d7 [2] 22 f5 [2] 24 c0 [2] 0a c0 [2] 35 dc }

  condition:
    any of them
}