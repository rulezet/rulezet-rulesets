rule TTP_XOR_WriteProcessMemory_5466 {
  strings:
    $key_5466 = { 03 14 [2] 31 36 [2] 37 03 [2] 19 03 [2] 26 1f }

  condition:
    any of them
}