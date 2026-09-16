rule TTP_XOR_WriteProcessMemory_6106 {
  strings:
    $key_6106 = { 36 74 [2] 04 56 [2] 02 63 [2] 2c 63 [2] 13 7f }

  condition:
    any of them
}