rule TTP_XOR_WriteProcessMemory_1466 {
  strings:
    $key_1466 = { 43 14 [2] 71 36 [2] 77 03 [2] 59 03 [2] 66 1f }

  condition:
    any of them
}