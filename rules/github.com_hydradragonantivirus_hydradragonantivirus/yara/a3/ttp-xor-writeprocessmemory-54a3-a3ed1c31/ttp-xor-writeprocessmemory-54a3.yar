rule TTP_XOR_WriteProcessMemory_54a3 {
  strings:
    $key_54a3 = { 03 d1 [2] 31 f3 [2] 37 c6 [2] 19 c6 [2] 26 da }

  condition:
    any of them
}