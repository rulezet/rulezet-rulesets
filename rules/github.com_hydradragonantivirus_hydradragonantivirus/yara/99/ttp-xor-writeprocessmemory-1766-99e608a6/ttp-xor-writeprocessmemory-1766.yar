rule TTP_XOR_WriteProcessMemory_1766 {
  strings:
    $key_1766 = { 40 14 [2] 72 36 [2] 74 03 [2] 5a 03 [2] 65 1f }

  condition:
    any of them
}