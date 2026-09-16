rule TTP_XOR_WriteProcessMemory_72a3 {
  strings:
    $key_72a3 = { 25 d1 [2] 17 f3 [2] 11 c6 [2] 3f c6 [2] 00 da }

  condition:
    any of them
}