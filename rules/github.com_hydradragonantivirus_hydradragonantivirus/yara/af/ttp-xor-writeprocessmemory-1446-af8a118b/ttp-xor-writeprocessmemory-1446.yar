rule TTP_XOR_WriteProcessMemory_1446 {
  strings:
    $key_1446 = { 43 34 [2] 71 16 [2] 77 23 [2] 59 23 [2] 66 3f }

  condition:
    any of them
}