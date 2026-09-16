rule TTP_XOR_WriteProcessMemory_6506 {
  strings:
    $key_6506 = { 32 74 [2] 00 56 [2] 06 63 [2] 28 63 [2] 17 7f }

  condition:
    any of them
}