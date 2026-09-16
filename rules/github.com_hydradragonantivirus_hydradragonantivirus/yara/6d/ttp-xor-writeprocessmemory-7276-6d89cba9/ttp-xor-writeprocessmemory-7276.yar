rule TTP_XOR_WriteProcessMemory_7276 {
  strings:
    $key_7276 = { 25 04 [2] 17 26 [2] 11 13 [2] 3f 13 [2] 00 0f }

  condition:
    any of them
}