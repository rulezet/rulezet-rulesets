rule TTP_XOR_WriteProcessMemory_72a5 {
  strings:
    $key_72a5 = { 25 d7 [2] 17 f5 [2] 11 c0 [2] 3f c0 [2] 00 dc }

  condition:
    any of them
}