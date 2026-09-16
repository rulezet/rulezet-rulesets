rule TTP_XOR_WriteProcessMemory_1476 {
  strings:
    $key_1476 = { 43 04 [2] 71 26 [2] 77 13 [2] 59 13 [2] 66 0f }

  condition:
    any of them
}