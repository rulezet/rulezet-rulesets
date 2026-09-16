rule TTP_XOR_WriteProcessMemory_1306 {
  strings:
    $key_1306 = { 44 74 [2] 76 56 [2] 70 63 [2] 5e 63 [2] 61 7f }

  condition:
    any of them
}