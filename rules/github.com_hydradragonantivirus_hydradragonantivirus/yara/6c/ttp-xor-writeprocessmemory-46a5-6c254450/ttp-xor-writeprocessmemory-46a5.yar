rule TTP_XOR_WriteProcessMemory_46a5 {
  strings:
    $key_46a5 = { 11 d7 [2] 23 f5 [2] 25 c0 [2] 0b c0 [2] 34 dc }

  condition:
    any of them
}