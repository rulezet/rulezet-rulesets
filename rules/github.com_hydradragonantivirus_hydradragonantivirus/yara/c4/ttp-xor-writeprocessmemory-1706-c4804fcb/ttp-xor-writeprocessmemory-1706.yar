rule TTP_XOR_WriteProcessMemory_1706 {
  strings:
    $key_1706 = { 40 74 [2] 72 56 [2] 74 63 [2] 5a 63 [2] 65 7f }

  condition:
    any of them
}