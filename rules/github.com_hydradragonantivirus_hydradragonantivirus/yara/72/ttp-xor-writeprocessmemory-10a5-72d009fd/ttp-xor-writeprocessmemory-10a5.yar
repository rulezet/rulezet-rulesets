rule TTP_XOR_WriteProcessMemory_10a5 {
  strings:
    $key_10a5 = { 47 d7 [2] 75 f5 [2] 73 c0 [2] 5d c0 [2] 62 dc }

  condition:
    any of them
}