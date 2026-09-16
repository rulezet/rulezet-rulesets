rule TTP_XOR_WriteProcessMemory_7481 {
  strings:
    $key_7481 = { 23 f3 [2] 11 d1 [2] 17 e4 [2] 39 e4 [2] 06 f8 }

  condition:
    any of them
}