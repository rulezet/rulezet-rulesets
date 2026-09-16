rule TTP_XOR_WriteProcessMemory_33a5 {
  strings:
    $key_33a5 = { 64 d7 [2] 56 f5 [2] 50 c0 [2] 7e c0 [2] 41 dc }

  condition:
    any of them
}