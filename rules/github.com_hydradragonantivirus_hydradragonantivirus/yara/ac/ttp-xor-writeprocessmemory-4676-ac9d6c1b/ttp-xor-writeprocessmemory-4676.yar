rule TTP_XOR_WriteProcessMemory_4676 {
  strings:
    $key_4676 = { 11 04 [2] 23 26 [2] 25 13 [2] 0b 13 [2] 34 0f }

  condition:
    any of them
}