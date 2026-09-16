rule TTP_XOR_WriteProcessMemory_45a3 {
  strings:
    $key_45a3 = { 12 d1 [2] 20 f3 [2] 26 c6 [2] 08 c6 [2] 37 da }

  condition:
    any of them
}