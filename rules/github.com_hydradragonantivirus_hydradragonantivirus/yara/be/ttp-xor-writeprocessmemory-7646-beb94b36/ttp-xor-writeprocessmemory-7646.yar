rule TTP_XOR_WriteProcessMemory_7646 {
  strings:
    $key_7646 = { 21 34 [2] 13 16 [2] 15 23 [2] 3b 23 [2] 04 3f }

  condition:
    any of them
}