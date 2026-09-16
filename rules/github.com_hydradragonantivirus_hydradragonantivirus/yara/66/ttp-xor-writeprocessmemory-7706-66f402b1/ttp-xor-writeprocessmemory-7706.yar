rule TTP_XOR_WriteProcessMemory_7706 {
  strings:
    $key_7706 = { 20 74 [2] 12 56 [2] 14 63 [2] 3a 63 [2] 05 7f }

  condition:
    any of them
}