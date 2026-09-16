rule TTP_XOR_WriteProcessMemory_5406 {
  strings:
    $key_5406 = { 03 74 [2] 31 56 [2] 37 63 [2] 19 63 [2] 26 7f }

  condition:
    any of them
}