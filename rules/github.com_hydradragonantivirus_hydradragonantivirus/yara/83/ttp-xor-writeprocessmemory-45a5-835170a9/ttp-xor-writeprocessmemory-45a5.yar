rule TTP_XOR_WriteProcessMemory_45a5 {
  strings:
    $key_45a5 = { 12 d7 [2] 20 f5 [2] 26 c0 [2] 08 c0 [2] 37 dc }

  condition:
    any of them
}