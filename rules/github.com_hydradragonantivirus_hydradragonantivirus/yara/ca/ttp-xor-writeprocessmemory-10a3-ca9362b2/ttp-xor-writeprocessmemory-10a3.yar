rule TTP_XOR_WriteProcessMemory_10a3 {
  strings:
    $key_10a3 = { 47 d1 [2] 75 f3 [2] 73 c6 [2] 5d c6 [2] 62 da }

  condition:
    any of them
}