rule TTP_XOR_WriteProcessMemory_0642 {
  strings:
    $key_0642 = { 51 30 [2] 63 12 [2] 65 27 [2] 4b 27 [2] 74 3b }

  condition:
    any of them
}