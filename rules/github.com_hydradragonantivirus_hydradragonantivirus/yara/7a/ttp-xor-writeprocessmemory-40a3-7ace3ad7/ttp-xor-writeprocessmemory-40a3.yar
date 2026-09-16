rule TTP_XOR_WriteProcessMemory_40a3 {
  strings:
    $key_40a3 = { 17 d1 [2] 25 f3 [2] 23 c6 [2] 0d c6 [2] 32 da }

  condition:
    any of them
}