rule TTP_XOR_WriteProcessMemory_30a5 {
  strings:
    $key_30a5 = { 67 d7 [2] 55 f5 [2] 53 c0 [2] 7d c0 [2] 42 dc }

  condition:
    any of them
}