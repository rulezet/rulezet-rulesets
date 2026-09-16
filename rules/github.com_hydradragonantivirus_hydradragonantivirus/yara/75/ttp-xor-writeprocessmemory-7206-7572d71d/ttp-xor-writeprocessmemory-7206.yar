rule TTP_XOR_WriteProcessMemory_7206 {
  strings:
    $key_7206 = { 25 74 [2] 17 56 [2] 11 63 [2] 3f 63 [2] 00 7f }

  condition:
    any of them
}