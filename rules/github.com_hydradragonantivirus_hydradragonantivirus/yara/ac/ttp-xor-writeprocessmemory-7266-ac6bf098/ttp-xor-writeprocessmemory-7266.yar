rule TTP_XOR_WriteProcessMemory_7266 {
  strings:
    $key_7266 = { 25 14 [2] 17 36 [2] 11 03 [2] 3f 03 [2] 00 1f }

  condition:
    any of them
}